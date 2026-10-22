package com.nine.dbt

import android.content.Context
import java.io.File

object ToolExecutor {
    private fun root(ctx: Context): File = ctx.filesDir.resolve("workspace").also { it.mkdirs() }

    fun run(ctx: Context, name: String, args: Map<String, String>): String {
        return try {
            when (name) {
                "search_web" -> searchWeb(args["query"] ?: "")
                "list_files" -> listFiles(ctx, args["path"] ?: ".")
                "read_file" -> readFile(ctx, args["path"] ?: "")
                "read_all_files" -> readAll(ctx, args["path"] ?: ".", args["pattern"] ?: ".*")
                "find_file" -> find(ctx, args["path"] ?: ".", args["pattern"] ?: ".*", firstOnly = true)
                "find_all_files" -> find(ctx, args["path"] ?: ".", args["pattern"] ?: ".*", firstOnly = false)
                "write_file" -> writeFile(ctx, args["path"] ?: "", args["content"] ?: "")
                "write_all_files" -> writeAll(ctx, args["manifest"] ?: args["files"] ?: "")
                "compile_extension" -> compileExtension(ctx, args["project_path"] ?: "")
                "compile_patch" -> compilePatch(ctx, args["project_path"] ?: "", args["base"] ?: "")
                "add_tool" -> addTool(ctx, args["name"] ?: "", args["code"] ?: "")
                else -> "Unknown tool: $name"
            }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    private fun searchWeb(query: String): String {
        if (query.isBlank()) return "query required"
        val url = java.net.URL("https://html.duckduckgo.com/html/?q=" + java.net.URLEncoder.encode(query, "UTF-8"))
        val conn = url.openConnection() as java.net.HttpURLConnection
        conn.requestMethod = "GET"
        conn.setRequestProperty("User-Agent", "NINE/1.0")
        conn.connectTimeout = 15000
        conn.readTimeout = 15000
        val body = conn.inputStream.bufferedReader().readText()
        conn.disconnect()
        val results = Regex("""<a[^>]*class="result__a"[^>]*>(.*?)</a>""", RegexOption.DOT_MATCHES_ALL)
            .findAll(body).take(5).map { it.groupValues[1].replace(Regex("<[^>]+>"), "").trim() }.toList()
        return if (results.isEmpty()) "No results" else results.joinToString("\n")
    }

    private fun resolve(ctx: Context, path: String): File {
        val f = File(path)
        return if (f.isAbsolute) f else File(root(ctx), path)
    }

    private fun listFiles(ctx: Context, path: String): String {
        val dir = resolve(ctx, path)
        if (!dir.exists()) return "Not found: $path"
        if (!dir.isDirectory) return "Not a directory: $path"
        return dir.listFiles()?.joinToString("\n") { it.name } ?: "(empty)"
    }

    private fun readFile(ctx: Context, path: String): String {
        val f = resolve(ctx, path)
        if (!f.exists()) return "Not found: $path"
        return f.readText().take(100_000)
    }

    private fun readAll(ctx: Context, path: String, pattern: String): String {
        val dir = resolve(ctx, path)
        val re = Regex(pattern)
        val files = dir.walkTopDown().filter { it.isFile && re.containsMatchIn(it.name) }.take(20)
        return files.joinToString("\n---\n") { "${it.name}:\n${it.readText().take(2000)}" }.ifEmpty { "No matches" }
    }

    private fun find(ctx: Context, path: String, pattern: String, firstOnly: Boolean): String {
        val dir = resolve(ctx, path)
        val re = Regex(pattern)
        val matches = dir.walkTopDown().filter { re.containsMatchIn(it.path) }
        return if (firstOnly) matches.firstOrNull()?.path ?: "Not found"
        else matches.take(50).joinToString("\n") { it.path }.ifEmpty { "No matches" }
    }

    private fun writeFile(ctx: Context, path: String, content: String): String {
        val f = resolve(ctx, path)
        f.parentFile?.mkdirs()
        f.writeText(content)
        return "Wrote ${f.length()} bytes to ${f.path}"
    }

    private fun writeAll(ctx: Context, manifest: String): String {
        // manifest format: path|||content---path|||content
        val parts = manifest.split("---")
        val written = mutableListOf<String>()
        for (part in parts) {
            val bits = part.split("|||", limit = 2)
            if (bits.size == 2) {
                writeFile(ctx, bits[0].trim(), bits[1])
                written += bits[0].trim()
            }
        }
        return "Wrote ${written.size} files: ${written.joinToString()}"
    }

    private fun compileExtension(ctx: Context, projectPath: String): String {
        val dir = resolve(ctx, projectPath)
        if (!dir.exists()) return "Project not found: $projectPath"
        val out = File(ctx.filesDir, "extensions").also { it.mkdirs() }
        val apk = File(out, "${dir.name}.apk")
        java.util.zip.ZipOutputStream(apk.outputStream()).use { zos ->
            dir.walkTopDown().filter { it.isFile }.forEach { f ->
                val entry = java.util.zip.ZipEntry(dir.toPath().relativize(f.toPath()).toString())
                zos.putNextEntry(entry)
                f.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
        }
        return try {
            ExtensionInstaller.installApk(ctx, apk)
            "Extension compiled and install session committed: ${apk.path} (${apk.length()} bytes)"
        } catch (e: Exception) {
            "Compiled ${apk.path} but install failed: ${e.message}"
        }
    }

    private fun compilePatch(ctx: Context, projectPath: String, base: String): String {
        val dir = resolve(ctx, projectPath)
        val out = File(ctx.filesDir, "patches").also { it.mkdirs() }
        val patch = File(out, "${if (dir.exists()) dir.name else "patch"}.patch")
        if (dir.exists() && dir.isDirectory) {
            val sb = StringBuilder()
            dir.walkTopDown().filter { it.isFile && it.extension == "patch" }.forEach { sb.append(it.readText()) }
            if (sb.isEmpty()) {
                dir.walkTopDown().filter { it.isFile }.forEach { f ->
                    sb.append("--- a/${f.name}\n+++ b/${f.name}\n")
                    f.readLines().forEach { sb.append("+").append(it).append("\n") }
                }
            }
            patch.writeText(sb.toString())
        } else if (dir.exists()) {
            dir.copyTo(patch, overwrite = true)
        } else return "Patch project not found: $projectPath"
        val baseText = if (base.isNotBlank()) {
            val bf = resolve(ctx, base)
            if (bf.exists()) bf.readText() else base
        } else ""
        val applied = ExtensionInstaller.applyPatch(ctx, patch, baseText)
        val appliedFile = File(out, "${patch.nameWithoutExtension}.applied")
        appliedFile.writeText(applied)
        return "Patch written to ${patch.path} and applied (${applied.length} chars) -> ${appliedFile.path}"
    }

    private fun addTool(ctx: Context, name: String, code: String): String {
        if (name.isBlank() || code.isBlank()) return "name and code required"
        val params = Regex("""fun\s+\w+\s*\(([^)]*)\)""")
            .find(code)?.groupValues?.getOrNull(1)
            ?.split(",")?.map { it.trim().substringBefore(":").substringBefore("=").trim() }
            ?.filter { it.isNotEmpty() }?.map { ToolParam(it) } ?: emptyList()
        val tools = AppStore.customTools(ctx)
        val existing = tools.indexOfFirst { it.name == name }
        val tool = AgenticTool(
            id = if (existing >= 0) tools[existing].id else System.currentTimeMillis().toString(),
            name = name, code = code, params = params, isBuiltin = false
        )
        if (existing >= 0) tools[existing] = tool else tools += tool
        AppStore.saveCustomTools(ctx, tools)
        return "Tool '$name' added (${params.size} params) and available now."
    }
}
