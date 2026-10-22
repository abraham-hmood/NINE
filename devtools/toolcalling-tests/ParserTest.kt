package com.nine.dbt

var fails = 0
fun check(label: String, cond: Boolean, detail: String = "") {
    if (!cond) { fails++; println("FAIL  $label  $detail") } else println("ok    $label")
}
fun main() {
    val tools = BuiltinTools.all
    fun p(s: String) = ToolCallParser.parse(s, tools)

    // 1. The exact thing from the bug report (single line, `--` separators, `files=` instead of `manifest=`)
    val bug = "tool write_all_files files=extensions/helloworld/nine-extension.json|||{\"id\": \"com.helloworld.example\",\"name\":\"Hello World Extension\", \"version\" : \"1.0.0\", \"entry\": \"com.example.helloworld.MainActivity\"}--extensions/helloworld/AndroidManifest.xml|||<manifest package=\"com.helloworld.example\"/>--extensions/helloworld/src/main/java/com/example/helloworld/MainActivity.kt|||package com.example.helloworld\nclass MainActivity"
    var r = p(bug)
    check("bug-report line: 1 call", r.calls.size == 1, r.calls.toString())
    check("bug-report: name", r.calls.firstOrNull()?.name == "write_all_files")
    check("bug-report: files->manifest", r.calls.firstOrNull()?.args?.containsKey("manifest") == true, r.calls.firstOrNull()?.args?.keys.toString())
    val files = ToolCallParser.parseManifest(r.calls.first().args["manifest"]!!)
    check("bug-report: 3 files", files.size == 3, files.map { it.first }.toString())
    check("bug-report: json intact", files[0].second.contains("\"name\":\"Hello World Extension\""))
    check("bug-report: no tool text left", r.text.isBlank(), "'${r.text}'")

    // 2. documented fenced format, multi-line content incl. nested fence + key-like text inside content
    r = p("Sure!\n```tool write_file\npath=src/Main.kt\ncontent=fun main() {\n  val text=\"hi\"\n  println(text)\n}\n```kotlin\nnested\n```\n```\nDone")
    check("fenced multi-line: 1 call", r.calls.size == 1, r.calls.toString())
    check("fenced: path", r.calls.firstOrNull()?.args?.get("path") == "src/Main.kt")
    check("fenced: content keeps text=", r.calls.firstOrNull()?.args?.get("content")?.contains("val text=\"hi\"") == true, r.calls.firstOrNull()?.args.toString())
    check("fenced: prose kept", r.text.contains("Sure!") && r.text.contains("Done"), r.text)

    // 3. Hermes / Qwen
    r = p("<tool_call>\n{\"name\": \"read_file\", \"arguments\": {\"path\": \"a.txt\"}}\n</tool_call>")
    check("hermes", r.calls.size == 1 && r.calls[0].name == "read_file" && r.calls[0].args["path"] == "a.txt", r.calls.toString())
    r = p("<tool_call>{\"name\": \"read_file\", \"arguments\": {\"path\": \"a.txt\"}}")   // EOS before closing tag
    check("hermes unterminated", r.calls.size == 1, r.calls.toString())

    // 4. Qwen-coder / Llama 3.1 function tags
    r = p("<tool_call>\n<function=write_file>\n<parameter=path>\nx.txt\n</parameter>\n<parameter=content>\nhello\n</parameter>\n</function>\n</tool_call>")
    check("qwen-coder xml", r.calls.size == 1 && r.calls[0].args["path"] == "x.txt" && r.calls[0].args["content"] == "hello", r.calls.toString())
    r = p("<function=search_web>{\"query\": \"kotlin\"}</function>")
    check("llama3.1 function tag", r.calls.size == 1 && r.calls[0].args["query"] == "kotlin", r.calls.toString())

    // 5. Anthropic-style invoke
    r = p("<function_calls>\n<invoke name=\"list_files\">\n<parameter name=\"path\">.</parameter>\n</invoke>\n</function_calls>")
    check("invoke xml", r.calls.size == 1 && r.calls[0].name == "list_files" && r.calls[0].args["path"] == ".", r.calls.toString())

    // 6. Mistral / Llama3 special tokens
    r = p("[TOOL_CALLS] [{\"name\": \"find_file\", \"arguments\": {\"path\": \".\", \"pattern\": \"\\\\.kt\$\"}}]")
    check("mistral", r.calls.size == 1 && r.calls[0].name == "find_file", r.calls.toString())
    r = p("<|python_tag|>{\"name\": \"read_file\", \"parameters\": {\"path\": \"b.txt\"}}<|eom_id|>")
    check("llama3 python_tag", r.calls.size == 1 && r.calls[0].args["path"] == "b.txt" && r.text.isEmpty(), r.calls.toString() + "|" + r.text)

    // 7. bare / fenced JSON, OpenAI shape, args as JSON string
    r = p("```json\n{\"name\":\"write_file\",\"arguments\":{\"path\":\"a\",\"content\":\"b\"}}\n```")
    check("json fence", r.calls.size == 1 && r.calls[0].args["content"] == "b", r.calls.toString())
    r = p("{\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"z\\\"}\"}}")
    check("openai shape", r.calls.size == 1 && r.calls[0].args["path"] == "z", r.calls.toString())
    r = p("I will call {\"name\":\"not_a_tool\",\"arguments\":{}} now")
    check("unknown json ignored", r.calls.isEmpty())

    // 8. python style, gemini default_api prefix
    r = p("print(default_api.write_file(path=\"a.txt\", content=\"line1\\nline2\"))")
    check("python style", r.calls.size == 1 && r.calls[0].args["content"] == "line1\nline2", r.calls.toString())
    r = p("You can use `read_file(path)` to read things.")
    check("prose mention NOT executed", r.calls.isEmpty(), r.calls.toString())

    // 9. fence header = tool name; args as JSON body; alias keys
    r = p("```write_file\n{\"file\": \"a.txt\", \"text\": \"hi\"}\n```")
    check("fence tool-name + alias json", r.calls.size == 1 && r.calls[0].args["path"] == "a.txt" && r.calls[0].args["content"] == "hi", r.calls.toString())
    r = p("```tool read_file path=a.txt```")
    check("same-line fence", r.calls.size == 1 && r.calls[0].args["path"] == "a.txt", r.calls.toString())

    // 10. several calls in one reply, thinking stripped
    r = p("<think>I should call write_file(path=\"no\", content=\"no\")</think>\n```tool write_file\npath=a\ncontent=b\n```\n```tool compile_extension\nproject_path=ext\n```")
    check("two calls, think ignored", r.calls.size == 2 && r.calls[0].name == "write_file" && r.calls[1].name == "compile_extension", r.calls.toString())

    // 11. plain answer has no calls
    r = p("Hello! Here is how extensions work: write files then compile.")
    check("plain text", r.calls.isEmpty() && r.text.startsWith("Hello"))

    // 12. manifests
    check("manifest json", ToolCallParser.parseManifest("[{\"path\":\"a.txt\",\"content\":\"hi\"}]").single().first == "a.txt")
    val m = ToolCallParser.parseManifest("a/b.txt|||l1\nl2\n---\nc-d/e.md|||---\ntitle: x\n---\nbody\n---\nf.txt|||z")
    check("manifest newline-separated", m.map { it.first } == listOf("a/b.txt", "c-d/e.md", "f.txt") && m[1].second == "---\ntitle: x\n---\nbody\n", m.toString())

    // 13. schema
    val js = BuiltinTools.toolsJson(emptyList())
    check("tools json", js.length() == 11 && js.getJSONObject(7).getJSONObject("function").getString("name") == "write_all_files")
    println(if (fails == 0) "\nALL PASSED" else "\n$fails FAILED")
}
