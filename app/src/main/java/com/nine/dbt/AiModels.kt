package com.nine.dbt

data class CloudModel(
    val id: String,
    val modelId: String,   // e.g. gpt-4o, gemini-1.5-flash
    val url: String,
    val apiKey: String
)

data class ToolParam(val name: String, val type: String = "string")

data class AgenticTool(
    val id: String,
    val name: String,
    val code: String,
    val params: List<ToolParam> = emptyList(),
    val isBuiltin: Boolean = false
)

data class ChatMessage(
    val id: String,
    val text: String,
    val fromUser: Boolean,
    val status: MessageStatus = MessageStatus.SENT
)

enum class MessageStatus { SENDING, SENT, THINKING, DONE }

object BuiltinTools {
    val all: List<AgenticTool> = listOf(
        tool("search_web", "Search the web.", listOf("query")),
        tool("list_files", "List files in a directory.", listOf("path")),
        tool("read_file", "Read a file.", listOf("path")),
        tool("read_all_files", "Read files matching a regex.", listOf("path", "pattern")),
        tool("find_file", "Find a file by regex.", listOf("path", "pattern")),
        tool("find_all_files", "Find all files matching a regex.", listOf("path", "pattern")),
        tool("write_file", "Write a file.", listOf("path", "content")),
        tool("write_all_files", "Write multiple files.", listOf("manifest")),
        tool("compile_extension", "Compile an extension APK and install it.", listOf("project_path")),
        tool("compile_patch", "Compile a .patch and apply it.", listOf("project_path", "base")),
        tool("add_tool", "Register a new agentic tool immediately.", listOf("name", "code"))
    )

    private fun tool(name: String, desc: String, params: List<String>) = AgenticTool(
        id = name,
        name = name,
        code = "// builtin: $desc",
        params = params.map { ToolParam(it) },
        isBuiltin = true
    )

    fun systemPrompt(extra: List<AgenticTool>): String {
        val names = (all + extra).joinToString(", ") { it.name }
        return """
You are the NINE Creator. You build three kinds of artifacts and then call the matching tool so they are applied immediately.

AVAILABLE TOOLS: $names
Call a tool by emitting a fenced block:
```tool tool_name
key=value
key=value
```
You may call several tools. After write_file / write_all_files, call compile_extension, compile_patch, or add_tool.

=== AGENTIC TOOL ===
A tool is a named function NINE can run.
Required:
- name: lowercase_with_underscores
- code: Kotlin-like function. First line must be `fun name(param1: String, param2: String): String {`
- params are inferred from that signature
- body returns a String
To register it, call:
```tool add_tool
name=my_tool
code=fun my_tool(path: String): String { return path }
```
It is saved and available immediately.

=== EXTENSION ===
An extension is an Android APK that NINE installs.
Project layout (under a folder you create with write_file):
- AndroidManifest.xml (package, one activity, android:exported)
- src/main/java/.../MainActivity.kt (or .java)
- nine-extension.json with {"id","name","version","entry"}
Build steps:
1. write_all_files with manifest `path|||content---path|||content`
2. call compile_extension with project_path=<that folder>
compile_extension packages the project into an APK and installs it via PackageInstaller immediately. Do not ask the user to install it.

=== APP PATCH ===
A patch is a unified diff (.patch) applied to NINE or to a text base.
Format:
--- a/relative/path
+++ b/relative/path
@@ -start,count +start,count @@
 context
-removed
+added
Build steps:
1. write_file the .patch content, or write the changed sources then compile_patch
2. call:
```tool compile_patch
project_path=patches/myfix
base=
```
compile_patch writes the .patch and applies it immediately to the base text (or stages it against the installed APK). Do not ask the user to apply it.

=== RULES ===
- Always finish by calling the compile/add tool. Creating files alone is not enough.
- Prefer write_all_files for multi-file projects.
- Paths are relative to the NINE workspace.
- Be precise. Output the tool blocks exactly.
        """.trimIndent()
    }
}
