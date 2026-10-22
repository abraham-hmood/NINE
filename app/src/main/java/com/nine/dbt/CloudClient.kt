package com.nine.dbt

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

object CloudClient {
    fun chat(ctx: Context, userMessage: String, history: List<ChatMessage>): String {
        val system = BuiltinTools.systemPrompt(AppStore.customTools(ctx))
        val raw = if (AppStore.useLocal(ctx)) {
            LocalAiEngine.generate(ctx, "$system\n\nUser: $userMessage")
        } else {
            callCloud(ctx, userMessage, history, system)
        }
        return runToolLoop(ctx, raw, userMessage)
    }

    private fun callCloud(ctx: Context, userMessage: String, history: List<ChatMessage>, system: String): String {
        val m = AppStore.activeCloud(ctx) ?: return "No cloud model configured. Add one in Settings → Cloud Models."
        val messages = JSONArray()
        messages.put(JSONObject().put("role", "system").put("content", system))
        history.takeLast(10).forEach {
            messages.put(JSONObject()
                .put("role", if (it.fromUser) "user" else "assistant")
                .put("content", it.text))
        }
        messages.put(JSONObject().put("role", "user").put("content", userMessage))
        val body = JSONObject().put("model", m.modelId).put("messages", messages)
        val endpoint = when {
            m.url.contains("/chat/completions") -> m.url
            m.url.contains("/openai") -> m.url.trimEnd('/') + "/chat/completions"
            else -> m.url.trimEnd('/') + "/v1/chat/completions"
        }
        val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            if (m.apiKey.isNotBlank()) setRequestProperty("Authorization", "Bearer ${m.apiKey}")
            connectTimeout = 30000
            readTimeout = 90000
        }
        conn.outputStream.use { it.write(body.toString().toByteArray()) }
        val code = conn.responseCode
        val stream = if (code in 200..299) conn.inputStream else conn.errorStream
        val resp = stream?.bufferedReader()?.readText() ?: ""
        conn.disconnect()
        if (code !in 200..299) return "API error $code: $resp"
        val root = JSONObject(resp)
        val msg = root.getJSONArray("choices").getJSONObject(0).getJSONObject("message")
        // Native tool_calls (OpenAI style) — execute them too.
        val toolCalls = msg.optJSONArray("tool_calls")
        if (toolCalls != null && toolCalls.length() > 0) {
            val sb = StringBuilder()
            for (i in 0 until toolCalls.length()) {
                val tc = toolCalls.getJSONObject(i).optJSONObject("function") ?: continue
                val name = tc.optString("name")
                val argsObj = tc.optJSONObject("arguments")
                    ?: try { JSONObject(tc.optString("arguments", "{}")) } catch (_: Exception) { JSONObject() }
                val args = argsObj.keys().asSequence().associateWith { argsObj.optString(it) }
                sb.append("[$name]\n${ToolExecutor.run(ctx, name, args)}\n\n")
            }
            return sb.toString().trim()
        }
        return msg.optString("content", "")
    }

    /** Parse and execute tool calls from any model (local or cloud). */
    private fun runToolLoop(ctx: Context, reply: String, userMessage: String): String {
        val calls = extractCalls(reply)
        if (calls.isEmpty()) return reply
        val sb = StringBuilder()
        // Keep any prose before the first tool block.
        val first = reply.indexOf("```tool")
        if (first > 0) sb.append(reply.substring(0, first).trim()).append("\n\n")
        for ((name, args) in calls) {
            val result = ToolExecutor.run(ctx, name, args)
            sb.append("[$name]\n$result\n\n")
            AppLog.i("tools", "$name -> ${result.take(120)}")
        }
        return sb.toString().trim()
    }

    private fun extractCalls(reply: String): List<Pair<String, Map<String, String>>> {
        val out = mutableListOf<Pair<String, Map<String, String>>>()
        // Fenced: ```tool name\nkey=value```  or  ```tool name key=value```
        val fenced = Regex("""```tool\s+(\w+)[ \t]*\n?(.*?)```""", RegexOption.DOT_MATCHES_ALL)
        for (m in fenced.findAll(reply)) {
            out += m.groupValues[1] to parseArgs(m.groupValues[2])
        }
        if (out.isNotEmpty()) return out
        // Unclosed fence or inline: ```tool name\n... until end
        val open = Regex("""```tool\s+(\w+)[ \t]*\n?(.*)""", RegexOption.DOT_MATCHES_ALL)
        val om = open.find(reply)
        if (om != null) {
            out += om.groupValues[1] to parseArgs(om.groupValues[2])
        }
        return out
    }

    private fun parseArgs(text: String): Map<String, String> {
        val args = mutableMapOf<String, String>()
        // key=value lines, or a single key=value with the rest of the body as the value
        val lines = text.trim().lines()
        if (lines.size == 1 && lines[0].contains("=")) {
            val p = lines[0].split("=", limit = 2)
            args[p[0].trim()] = p[1]
            return args
        }
        var currentKey: String? = null
        val buf = StringBuilder()
        fun flush() {
            if (currentKey != null) args[currentKey!!] = buf.toString().trim()
            buf.clear()
        }
        for (line in lines) {
            val eq = line.indexOf('=')
            if (eq > 0 && !line.substring(0, eq).contains(' ')) {
                flush()
                currentKey = line.substring(0, eq).trim()
                buf.append(line.substring(eq + 1))
            } else if (currentKey != null) {
                buf.append('\n').append(line)
            }
        }
        flush()
        return args
    }
}
