package com.nine.dbt

import org.json.JSONArray
import org.json.JSONObject

data class ToolCall(val name: String, val args: Map<String, String>, val id: String = "")

data class ParsedReply(val text: String, val calls: List<ToolCall>)

/**
 * Extracts tool calls from model output no matter which dialect the model speaks:
 *  - fenced  ```tool name\nkey=value```  (the app's documented format)
 *  - fenced JSON  ```json {"name":..,"arguments":{..}}```
 *  - <tool_call>{json}</tool_call>   (Hermes / Qwen / many fine-tunes)
 *  - <function=name><parameter=k>v</parameter></function>   (Qwen-coder / Llama 3.1)
 *  - <invoke name="x"><parameter name="k">v</parameter></invoke>
 *  - [TOOL_CALLS][{..}]  (Mistral),  <|python_tag|>{..}  (Llama 3)
 *  - bare JSON objects  {"name":"write_file","arguments":{..}}  (any JSON-capable model)
 *  - bare lines  `tool write_file path=a.txt content=...`
 *  - python style  write_file(path="a.txt", content="...")
 */
object ToolCallParser {

    private class Hit(val start: Int, val end: Int, val calls: List<ToolCall>)

    private val TOOL_TAGS = setOf(
        "tool", "tool_call", "toolcall", "tool_use", "function", "function_call", "call", "action", "tools"
    )
    private val MARKERS = listOf(
        "[TOOL_CALLS]", "<|python_tag|>", "<|eom_id|>", "<|eot_id|>", "<|im_end|>", "<|im_start|>assistant"
    )
    private val NAME_KEYS = listOf("name", "tool", "tool_name", "function", "function_name", "action", "recipient_name")
    private val ARG_KEYS = listOf("arguments", "parameters", "args", "input", "params", "tool_input", "action_input")

    /** alias -> candidate canonical parameter names (first one the tool actually has wins) */
    private val ALIASES: Map<String, List<String>> = mapOf(
        "file" to listOf("path"), "filename" to listOf("path"), "file_path" to listOf("path"),
        "filepath" to listOf("path"), "file_name" to listOf("path"), "dir" to listOf("path", "project_path"),
        "directory" to listOf("path", "project_path"), "folder" to listOf("path", "project_path"),
        "location" to listOf("path"), "root" to listOf("path"),
        "text" to listOf("content", "query"), "data" to listOf("content", "code"),
        "contents" to listOf("content"), "body" to listOf("content", "code"), "source" to listOf("code", "content"),
        "files" to listOf("manifest", "path"), "file_manifest" to listOf("manifest"),
        "entries" to listOf("manifest"), "file_list" to listOf("manifest"), "bundle" to listOf("manifest"),
        "project" to listOf("project_path", "manifest"), "project_dir" to listOf("project_path"),
        "project_name" to listOf("project_path"), "extension_path" to listOf("project_path"),
        "extension" to listOf("project_path"),
        "q" to listOf("query"), "search" to listOf("query"), "search_query" to listOf("query"),
        "keywords" to listOf("query"), "keyword" to listOf("query"),
        "regex" to listOf("pattern"), "glob" to listOf("pattern"), "filter" to listOf("pattern"),
        "match" to listOf("pattern"),
        "base_text" to listOf("base"), "base_path" to listOf("base"), "target" to listOf("base"),
        "tool_name" to listOf("name"), "function" to listOf("code"), "implementation" to listOf("code")
    )

    // ------------------------------------------------------------------ public API

    fun parse(raw: String, tools: List<AgenticTool>): ParsedReply {
        val text = stripThinking(raw)
        val schema = tools.associate { it.name to it.params.map { p -> p.name } }
        val hits = mutableListOf<Hit>()
        fun add(h: Hit) {
            if (h.calls.isNotEmpty() && hits.none { it.start < h.end && h.start < it.end }) hits += h
        }
        fencedHits(text, schema).forEach { add(it) }
        xmlHits(text, schema).forEach { add(it) }
        jsonHits(text, schema).forEach { add(it) }
        lineHits(text, schema).forEach { add(it) }
        pythonHits(text, schema).forEach { add(it) }
        hits.sortBy { it.start }

        val sb = StringBuilder()
        var pos = 0
        for (h in hits) {
            if (h.start > pos) sb.append(text, pos, h.start)
            pos = maxOf(pos, h.end)
        }
        if (pos < text.length) sb.append(text, pos, text.length)
        var visible = sb.toString()
        for (m in MARKERS) visible = visible.replace(m, "")
        visible = visible.replace(Regex("\n{3,}"), "\n\n").trim()

        val calls = hits.flatMap { it.calls }.mapIndexed { i, c ->
            val resolved = resolveName(c.name, schema.keys) ?: c.name
            ToolCall(resolved, normalizeArgs(c.args, schema[resolved]), "call_${i}_${resolved}")
        }
        return ParsedReply(visible, calls)
    }

    /** Remove model reasoning blocks so tool calls inside chain-of-thought are not executed. */
    fun stripThinking(s: String): String {
        var t = s.replace(Regex("(?s)<think(?:ing)?>.*?</think(?:ing)?>"), "")
        val open = Regex("<think(?:ing)?>").find(t)
        if (open != null) t = t.substring(0, open.range.first)
        return t
    }

    /** If a local model hallucinates the tool output after its call, drop everything from there on. */
    fun cutHallucinatedResults(s: String): String {
        val m = Regex("(?im)^\\s*(?:\\[?tool[ _]?results?\\]?|<tool_response>|<\\|tool_response\\|>|observation:)").find(s)
        return if (m != null && m.range.first > 0) s.substring(0, m.range.first) else s
    }

    fun resolveName(raw: String?, known: Collection<String>): String? {
        if (raw == null) return null
        var n = raw.trim().trim('"', '\'', '`')
        for (p in listOf("functions.", "functions:", "tools.", "default_api.", "tool.", "function.")) {
            if (n.startsWith(p, ignoreCase = true)) n = n.substring(p.length)
        }
        n = n.replace('-', '_')
        return known.firstOrNull { it.equals(n, ignoreCase = true) }
    }

    fun normalizeArgs(raw: Map<String, String>, params: List<String>?): Map<String, String> {
        if (params == null) return raw
        val out = LinkedHashMap<String, String>()
        val leftovers = LinkedHashMap<String, String>()
        for ((k0, v) in raw) {
            val k = k0.trim()
            if (k in params) { out[k] = v; continue }
            val lk = k.lowercase().replace('-', '_')
            val exact = params.firstOrNull { it.equals(lk, ignoreCase = true) }
            if (exact != null) { out[exact] = v; continue }
            val target = ALIASES[lk]?.firstOrNull { it in params && it !in raw && it !in out }
            if (target != null) out[target] = v else leftovers[k] = v
        }
        // exactly one param and exactly one stray value: it can only mean that param
        if (params.size == 1 && params[0] !in out && leftovers.size == 1) out[params[0]] = leftovers.values.first()
        for ((k, v) in leftovers) if (k !in out) out[k] = v
        return out
    }

    /** Calls from an OpenAI-style `tool_calls` array (or a wrapped legacy `function_call`). */
    fun nativeCalls(arr: JSONArray): List<ToolCall> = callsFromJson(arr, emptyMap(), strict = false)

    fun describe(c: ToolCall): String {
        val a = c.args.entries.joinToString(" ") { (k, v) ->
            val one = v.replace("\n", "⏎")
            "$k=" + if (one.length > 60) one.take(57) + "…(${v.length} chars)" else one
        }
        return "⚙ ${c.name} $a".trim()
    }

    // ------------------------------------------------------------------ manifest (write_all_files)

    /**
     * Accepts a JSON array/object of files, or `path|||content` entries separated by `---`,
     * `--`, a newline, or nothing at all.
     */
    fun parseManifest(manifest: String): List<Pair<String, String>> {
        val t = manifest.trim()
        if (t.startsWith("[") || t.startsWith("{")) {
            try {
                val any: Any = if (t.startsWith("[")) JSONArray(t) else JSONObject(t)
                val list = manifestFromJson(any)
                if (list.isNotEmpty()) return list
            } catch (_: Exception) { }
        }
        class Entry(val path: String, val sepStart: Int, val contentStart: Int, val hadDashes: Boolean)
        val entries = mutableListOf<Entry>()
        val pathRe = Regex("([^\\s|]+)\\|\\|\\|")
        val dashRe = Regex("-{2,}")
        val okPath = Regex("[\\w./@+~\\-]+")
        for (m in pathRe.findAll(manifest)) {
            val g = m.groupValues[1]
            val d = dashRe.findAll(g).lastOrNull()
            val p = if (d != null) g.substring(d.range.last + 1) else g
            val sep = if (d != null) m.range.first + d.range.first else m.range.first
            if (p.isEmpty() || !okPath.matches(p)) continue
            entries += Entry(p, sep, m.range.last + 1, d != null)
        }
        val out = mutableListOf<Pair<String, String>>()
        for ((i, e) in entries.withIndex()) {
            val end = if (i + 1 < entries.size) entries[i + 1].sepStart else manifest.length
            var c = manifest.substring(e.contentStart, maxOf(e.contentStart, end))
            c = c.removePrefix("\r\n").removePrefix("\n")
            if (i + 1 < entries.size && !entries[i + 1].hadDashes) c = c.replace(Regex("\\s*-{2,}\\s*$"), "")
            out += e.path to (c.trimEnd() + "\n")
        }
        return out
    }

    private fun manifestFromJson(any: Any): List<Pair<String, String>> {
        val out = mutableListOf<Pair<String, String>>()
        when (any) {
            is JSONArray -> for (i in 0 until any.length()) {
                val o = any.optJSONObject(i) ?: continue
                val p = o.optString("path", o.optString("name", o.optString("file", "")))
                if (p.isNotBlank()) out += p to (if (o.isNull("content")) "" else o.optString("content", ""))
            }
            is JSONObject -> {
                if (any.has("files")) return manifestFromJson(any.get("files"))
                for (k in any.keys()) {
                    val v = any.get(k)
                    out += k to (if (v is String) v else v.toString())
                }
            }
        }
        return out
    }

    // ------------------------------------------------------------------ fenced blocks

    private fun fencedHits(text: String, schema: Map<String, List<String>>): List<Hit> {
        val out = mutableListOf<Hit>()
        var i = 0
        while (i < text.length) {
            val open = text.indexOf("```", i)
            if (open < 0) break
            var nl = text.indexOf('\n', open)
            if (nl < 0) nl = text.length
            var header = text.substring(open + 3, nl).trim()
            val single = header.endsWith("```") && header.length > 3        // ```tool read_file path=a```
            if (single) header = header.removeSuffix("```").trim()
            val (bodyEnd, closeEnd) = when {
                single -> nl to nl
                nl >= text.length -> text.length to text.length
                else -> findClose(text, nl + 1)
            }
            val body = if (single || nl >= text.length) "" else text.substring(nl + 1, minOf(bodyEnd, text.length).coerceAtLeast(nl + 1))
            i = maxOf(closeEnd, nl + 1)
            val tokens = header.split(Regex("\\s+")).filter { it.isNotEmpty() }
            val tag = tokens.firstOrNull()?.lowercase() ?: ""
            var calls: List<ToolCall> = emptyList()
            when {
                tag in TOOL_TAGS && tokens.size >= 2 -> {
                    val name = tokens[1]
                    val inline = tokens.drop(2).joinToString(" ")
                    val full = if (inline.isNotEmpty()) inline + "\n" + body else body
                    calls = listOf(ToolCall(name, parseArgBody(full, schema[resolveName(name, schema.keys)] ?: emptyList(), name, schema)))
                }
                resolveName(tokens.firstOrNull(), schema.keys) != null -> {
                    val name = tokens[0]
                    val inline = tokens.drop(1).joinToString(" ")
                    val full = if (inline.isNotEmpty()) inline + "\n" + body else body
                    calls = listOf(ToolCall(name, parseArgBody(full, schema[resolveName(name, schema.keys)] ?: emptyList(), name, schema)))
                }
                tag in TOOL_TAGS || tag == "json" || tag.isEmpty() -> {
                    val strict = !(tag in TOOL_TAGS)
                    calls = jsonCallsFromText(body, schema, strict)
                    if (calls.isEmpty() && tag in TOOL_TAGS) {
                        val first = body.lineSequence().firstOrNull { it.isNotBlank() }?.trim()
                        val nm = first?.split(Regex("\\s+"))?.firstOrNull()
                        if (nm != null && resolveName(nm, schema.keys) != null) {
                            val rest = body.substringAfter(first!!).let { (first.removePrefix(nm).trim() + "\n" + it.trimStart('\n')) }
                            calls = listOf(ToolCall(nm, parseArgBody(rest, schema[resolveName(nm, schema.keys)] ?: emptyList(), nm, schema)))
                        }
                    }
                }
            }
            if (calls.isNotEmpty()) out += Hit(open, closeEnd, calls)
        }
        return out
    }

    /** returns (bodyEnd, closeEnd); handles nested fences inside file content */
    private fun findClose(text: String, from: Int): Pair<Int, Int> {
        var depth = 0
        var pos = from
        while (pos < text.length) {
            val eol = text.indexOf('\n', pos).let { if (it < 0) text.length else it }
            val line = text.substring(pos, eol)
            val t = line.trim()
            if (t == "```") {
                if (depth == 0) return pos to eol
                depth--
            } else if (t.startsWith("```")) {
                val tag = t.removePrefix("```").trim().split(Regex("\\s+")).first().lowercase()
                if (depth == 0 && (tag in TOOL_TAGS)) return pos to pos   // previous block was never closed
                depth++
            } else if (depth == 0 && t.endsWith("```")) {
                val idx = line.lastIndexOf("```")
                return (pos + idx) to eol
            }
            pos = eol + 1
        }
        return text.length to text.length
    }

    // ------------------------------------------------------------------ key=value bodies

    /** body is either a JSON object of args or key=value text. */
    private fun parseArgBody(body: String, params: List<String>, toolName: String, schema: Map<String, List<String>>): Map<String, String> {
        val t = body.trim()
        if (t.startsWith("{")) {
            try {
                val o = JSONObject(t)
                val nested = ARG_KEYS.firstOrNull { o.has(it) && o.opt(it) is JSONObject }
                return jsonToMap(if (nested != null) o.getJSONObject(nested) else o)
            } catch (_: Exception) { }
        }
        return parseKeyValues(body, params, lineStartOnly = body.contains('\n'))
    }

    private fun candidateKeys(params: List<String>): Map<String, Int> {
        val m = LinkedHashMap<String, Int>()
        params.forEachIndexed { i, p -> m[p.lowercase()] = i }
        for ((alias, targets) in ALIASES) {
            val t = targets.firstOrNull { it in params } ?: continue
            if (alias !in m) m[alias] = params.indexOf(t)
        }
        return m
    }

    /**
     * Splits `k=v k2=v2` (inline) or multi-line `k=v` bodies. Once the LAST declared parameter
     * has been seen, everything after belongs to it, so code like `text="x"` inside file
     * content is never mistaken for a new argument.
     */
    fun parseKeyValues(s: String, params: List<String>, lineStartOnly: Boolean): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        val cand = candidateKeys(params)
        val generic = cand.isEmpty()
        val keyAlt = if (generic) "[A-Za-z_][\\w\\-]*" else cand.keys.joinToString("|") { Regex.escape(it) }
        val re = if (lineStartOnly)
            Regex("(?im)^[ \\t]*($keyAlt)[ \\t]*[=:][ \\t]?")
        else
            Regex("(?i)(?:^|(?<=\\s))($keyAlt)=")
        val lastIdx = params.size - 1
        val seen = mutableSetOf<Int>()
        class Seg(val key: String, val vStart: Int, val mStart: Int)
        val segs = mutableListOf<Seg>()
        var stop = false
        for (m in re.findAll(s)) {
            if (stop) break
            val k = m.groupValues[1]
            val idx = if (generic) segs.size else (cand[k.lowercase()] ?: continue)
            if (!generic && idx in seen) continue
            // ':' separators only count for real parameter names, never aliases
            if (lineStartOnly && !generic && m.value.contains(':') && !m.value.contains('=') && k.lowercase() !in params.map { it.lowercase() }) continue
            seen += idx
            segs += Seg(k, m.range.last + 1, m.range.first)
            if (!generic && idx == lastIdx) stop = true
        }
        for ((i, sg) in segs.withIndex()) {
            val end = if (i + 1 < segs.size) segs[i + 1].mStart else s.length
            var v = s.substring(sg.vStart, maxOf(sg.vStart, end))
            v = if (lineStartOnly) v.trimEnd('\n', '\r', ' ') else v.trim()
            out[sg.key] = unquote(v)
        }
        return out
    }

    private fun unquote(v: String): String {
        if (v.length >= 2 && !v.contains('\n')) {
            val q = v[0]
            if ((q == '"' || q == '\'') && v.last() == q) {
                val inner = v.substring(1, v.length - 1)
                if (q == '"') try { return JSONObject("{\"v\":$v}").getString("v") } catch (_: Exception) { }
                return inner
            }
        }
        return v
    }

    // ------------------------------------------------------------------ XML-ish dialects

    private fun xmlHits(text: String, schema: Map<String, List<String>>): List<Hit> {
        val out = mutableListOf<Hit>()
        val wrap = Regex("(?s)<(tool_call|toolcall|tool_use|function_call|function_calls|tool_calls)>(.*?)(?:</\\1>|\\z)")
        for (m in wrap.findAll(text)) {
            val calls = callsFromXmlBody(m.groupValues[2], schema)
            if (calls.isNotEmpty()) out += Hit(m.range.first, m.range.last + 1, calls)
        }
        val fn = Regex("(?s)<function=([\\w.\\-]+)>(.*?)</function>")
        for (m in fn.findAll(text)) out += Hit(m.range.first, m.range.last + 1,
            listOf(ToolCall(m.groupValues[1], xmlArgs(m.groupValues[2], m.groupValues[1], schema))))
        val inv = Regex("(?s)<invoke\\s+name=[\"']([\\w.\\-]+)[\"']\\s*>(.*?)</invoke>")
        for (m in inv.findAll(text)) out += Hit(m.range.first, m.range.last + 1,
            listOf(ToolCall(m.groupValues[1], xmlArgs(m.groupValues[2], m.groupValues[1], schema))))
        val tn = Regex("(?s)<(?:tool|function_call)\\s+name=[\"']([\\w.\\-]+)[\"']\\s*>(.*?)</(?:tool|function_call)>")
        for (m in tn.findAll(text)) out += Hit(m.range.first, m.range.last + 1,
            listOf(ToolCall(m.groupValues[1], xmlArgs(m.groupValues[2], m.groupValues[1], schema))))
        return out
    }

    private fun callsFromXmlBody(body: String, schema: Map<String, List<String>>): List<ToolCall> {
        val j = jsonCallsFromText(body, schema, strict = false)
        if (j.isNotEmpty()) return j
        val res = mutableListOf<ToolCall>()
        Regex("(?s)<function=([\\w.\\-]+)>(.*?)</function>").findAll(body).forEach {
            res += ToolCall(it.groupValues[1], xmlArgs(it.groupValues[2], it.groupValues[1], schema))
        }
        Regex("(?s)<invoke\\s+name=[\"']([\\w.\\-]+)[\"']\\s*>(.*?)</invoke>").findAll(body).forEach {
            res += ToolCall(it.groupValues[1], xmlArgs(it.groupValues[2], it.groupValues[1], schema))
        }
        if (res.isNotEmpty()) return res
        val first = body.lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: return emptyList()
        val nm = first.split(Regex("\\s+")).first()
        if (resolveName(nm, schema.keys) == null) return emptyList()
        val rest = first.removePrefix(nm).trim() + "\n" + body.substringAfter(first).trimStart('\n')
        return listOf(ToolCall(nm, parseArgBody(rest, schema[resolveName(nm, schema.keys)] ?: emptyList(), nm, schema)))
    }

    private fun xmlArgs(inner: String, name: String, schema: Map<String, List<String>>): Map<String, String> {
        val params = Regex("(?s)<parameter(?:=|\\s+name=)[\"']?([\\w\\-]+)[\"']?\\s*>(.*?)</parameter>")
            .findAll(inner).toList()
        if (params.isNotEmpty()) {
            return params.associate { it.groupValues[1] to it.groupValues[2].removePrefix("\n").removeSuffix("\n") }
        }
        val t = inner.trim()
        if (t.startsWith("{")) try { return jsonToMap(JSONObject(t)) } catch (_: Exception) { }
        return parseKeyValues(inner, schema[resolveName(name, schema.keys)] ?: emptyList(), inner.contains('\n'))
    }

    // ------------------------------------------------------------------ JSON dialects

    private fun jsonToMap(o: JSONObject): Map<String, String> {
        val m = LinkedHashMap<String, String>()
        for (k in o.keys()) {
            val v = o.get(k)
            m[k] = when {
                v == JSONObject.NULL -> ""
                v is String -> v
                else -> v.toString()
            }
        }
        return m
    }

    private fun jsonCallsFromText(s: String, schema: Map<String, List<String>>, strict: Boolean): List<ToolCall> {
        val t = s.trim()
        return try {
            when {
                t.startsWith("[") -> callsFromJson(JSONArray(t), schema, strict)
                t.startsWith("{") -> callsFromJson(JSONObject(t), schema, strict)
                else -> emptyList()
            }
        } catch (_: Exception) { emptyList() }
    }

    private fun callsFromJson(any: Any, schema: Map<String, List<String>>, strict: Boolean): List<ToolCall> {
        val out = mutableListOf<ToolCall>()
        when (any) {
            is JSONArray -> for (i in 0 until any.length()) any.optJSONObject(i)?.let { out += callsFromJson(it, schema, strict) }
            is JSONObject -> {
                val tc = any.optJSONArray("tool_calls")
                if (tc != null) return callsFromJson(tc, schema, strict)
                val fnObj = any.optJSONObject("function")
                val src = fnObj ?: any
                var name: String? = null
                for (k in NAME_KEYS) {
                    val v = src.opt(k)
                    if (v is String && v.isNotBlank()) { name = v; break }
                }
                if (name == null) return out
                val resolved = resolveName(name, schema.keys)
                if (strict && resolved == null) return out
                var args: Map<String, String>? = null
                for (k in ARG_KEYS) {
                    if (!src.has(k) && !any.has(k)) continue
                    val v = if (src.has(k)) src.get(k) else any.get(k)
                    args = when (v) {
                        is JSONObject -> jsonToMap(v)
                        is String -> try { jsonToMap(JSONObject(v)) } catch (_: Exception) {
                            parseKeyValues(v, schema[resolved] ?: emptyList(), v.contains('\n'))
                        }
                        else -> null
                    }
                    break
                }
                if (args == null) {
                    // {"name":"read_file","path":"a.txt"} - extra keys are the arguments
                    args = jsonToMap(src).filterKeys { it !in NAME_KEYS && it != "type" && it != "id" }
                }
                out += ToolCall(name, args, any.optString("id", ""))
            }
        }
        return out
    }

    private fun jsonHits(text: String, schema: Map<String, List<String>>): List<Hit> {
        val out = mutableListOf<Hit>()
        var i = 0
        val keywords = listOf("\"name\"", "\"tool\"", "\"function\"", "\"tool_calls\"", "\"tool_name\"", "\"action\"")
        while (i < text.length) {
            val c = text[i]
            if (c != '{' && c != '[') { i++; continue }
            val window = text.substring(i, minOf(text.length, i + 400))
            if (keywords.none { window.contains(it) }) { i++; continue }
            val end = matchBracket(text, i)
            if (end < 0) { i++; continue }
            val calls = jsonCallsFromText(text.substring(i, end + 1), schema, strict = true)
            if (calls.isNotEmpty()) { out += Hit(i, end + 1, calls); i = end + 1 } else i++
        }
        return out
    }

    private fun matchBracket(s: String, start: Int): Int {
        var depth = 0
        var inStr = false
        var esc = false
        for (i in start until s.length) {
            val ch = s[i]
            if (inStr) {
                if (esc) esc = false else if (ch == '\\') esc = true else if (ch == '"') inStr = false
                continue
            }
            when (ch) {
                '"' -> inStr = true
                '{', '[' -> depth++
                '}', ']' -> { depth--; if (depth == 0) return i }
            }
        }
        return -1
    }

    // ------------------------------------------------------------------ bare line + python dialects

    private fun lineHits(text: String, schema: Map<String, List<String>>): List<Hit> {
        if (schema.isEmpty()) return emptyList()
        val names = schema.keys.joinToString("|") { Regex.escape(it) }
        val head = Regex("(?im)^[ \\t>*•\\-]*(?:tool_call|tool|call|use|run|invoke|calling)\\b[ \\t:]*(?:default_api\\.|functions\\.)?($names)\\b[ \\t]*")
        val starts = head.findAll(text).toList()
        val out = mutableListOf<Hit>()
        for ((i, m) in starts.withIndex()) {
            val name = m.groupValues[1]
            val argStart = m.range.last + 1
            var end = if (i + 1 < starts.size) starts[i + 1].range.first else text.length
            val fence = Regex("(?m)^[ \\t]*```[ \\t]*$").find(text, argStart)
            if (fence != null && fence.range.first < end) end = fence.range.first
            var raw = text.substring(argStart, maxOf(argStart, end)).trimEnd()
            if (raw.startsWith("(") && raw.endsWith(")")) raw = raw.substring(1, raw.length - 1)
            val params = schema[name] ?: emptyList()
            val args = if (raw.trim().startsWith("{")) {
                try { jsonToMap(JSONObject(raw.trim())) } catch (_: Exception) { parseKeyValues(raw, params, raw.contains('\n')) }
            } else parseKeyValues(raw, params, raw.contains('\n'))
            out += Hit(m.range.first, maxOf(m.range.last + 1, end), listOf(ToolCall(name, args)))
        }
        return out
    }

    private fun pythonHits(text: String, schema: Map<String, List<String>>): List<Hit> {
        if (schema.isEmpty()) return emptyList()
        val names = schema.keys.joinToString("|") { Regex.escape(it) }
        val re = Regex("(?:\\b(?:default_api|functions|tools)\\.)?\\b($names)\\s*\\(")
        val out = mutableListOf<Hit>()
        var from = 0
        while (true) {
            val m = re.find(text, from) ?: break
            val name = m.groupValues[1]
            val parsed = parsePyArgs(text, m.range.last + 1, schema[name] ?: emptyList())
            if (parsed == null) { from = m.range.last + 1; continue }
            val (args, endIdx) = parsed
            if (args.isEmpty()) { from = endIdx; continue }
            out += Hit(m.range.first, endIdx, listOf(ToolCall(name, args)))
            from = endIdx
        }
        return out
    }

    private fun parsePyArgs(s: String, start: Int, params: List<String>): Pair<Map<String, String>, Int>? {
        val out = LinkedHashMap<String, String>()
        var i = start
        var positional = 0
        while (i < s.length) {
            while (i < s.length && (s[i].isWhitespace() || s[i] == ',')) i++
            if (i >= s.length) return null
            if (s[i] == ')') return out to (i + 1)
            var key: String? = null
            val km = Regex("([A-Za-z_]\\w*)\\s*=(?!=)\\s*").matchAt(s, i)
            if (km != null) { key = km.groupValues[1]; i = km.range.last + 1 }
            val (value, next) = readPyValue(s, i) ?: return null
            i = next
            if (key == null) { key = params.getOrNull(positional) ?: return null; positional++ }
            out[key] = value
        }
        return null
    }

    private fun readPyValue(s: String, start: Int): Pair<String, Int>? {
        if (start >= s.length) return null
        val c = s[start]
        if (s.startsWith("\"\"\"", start) || s.startsWith("'''", start)) {
            val q = s.substring(start, start + 3)
            val e = s.indexOf(q, start + 3)
            if (e < 0) return null
            return s.substring(start + 3, e).removePrefix("\n") to (e + 3)
        }
        if (c == '"' || c == '\'') {
            val sb = StringBuilder()
            var i = start + 1
            while (i < s.length) {
                val ch = s[i]
                if (ch == '\\' && i + 1 < s.length) {
                    when (val n = s[i + 1]) {
                        'n' -> sb.append('\n'); 't' -> sb.append('\t'); 'r' -> sb.append('\r')
                        else -> sb.append(n)
                    }
                    i += 2; continue
                }
                if (ch == c) return sb.toString() to (i + 1)
                sb.append(ch); i++
            }
            return null
        }
        if (c == '{' || c == '[') {
            val e = matchBracket(s, start)
            if (e < 0) return null
            return s.substring(start, e + 1) to (e + 1)
        }
        return null   // bare identifiers (e.g. `read_file(path)` in prose) are not real calls
    }
}
