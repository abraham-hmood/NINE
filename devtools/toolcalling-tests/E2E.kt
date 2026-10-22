package com.nine.dbt
import android.content.Context
import java.io.File
fun main() {
    val ctx = Context()
    File("/tmp/nine_files").deleteRecursively()
    var fails = 0
    fun check(l: String, c: Boolean, d: String = "") { if (!c) { fails++; println("FAIL $l $d") } else println("ok   $l") }
    fun run(scen: String, msg: String = "make it"): Pair<String, List<String>> {
        AppStore.url = "http://127.0.0.1:8765/$scen/v1/chat/completions"
        val steps = mutableListOf<String>()
        val r = CloudClient.chat(ctx, msg, emptyList()) { steps += it }
        return r to steps
    }
    val ws = File("/tmp/nine_files/workspace")

    var (r, steps) = run("native")
    check("native: final text", r == "All done (native).", r)
    check("native: file written", File(ws, "native/a.txt").readText() == "from native")
    check("native: steps shown", steps.size == 2 && steps[0].startsWith("⚙ write_file") && steps[1].startsWith("↳ Wrote"), steps.toString())

    run("textonly").also { r = it.first; steps = it.second }
    check("text fallback: final", r == "All done (text).", r)
    check("text fallback: manifest written", File(ws, "extensions/helloworld/AndroidManifest.xml").exists())
    check("text fallback: json written", File(ws, "extensions/helloworld/nine-extension.json").readText().contains("Hello World Extension"))
    check("text fallback: compile ran", steps.any { it.contains("compile_extension") } && steps.any { it.contains("install session committed") || it.contains("Extension compiled") }, steps.toString())

    run("ignores").also { r = it.first; steps = it.second }
    check("ignores-tools model: hermes call executed", File(ws, "ign/b.txt").readText() == "from hermes" && r == "All done (ignores).", r)

    run("loop").also { r = it.first; steps = it.second }
    check("runaway loop is stopped", r.startsWith("Stopped") || r.contains("already been made") || steps.any { it.contains("already been made") }, r + steps.takeLast(2))

    r = run("native", "please make sure write_file works").first   // mention must not auto-run anything extra
    check("mentioning a tool name does not execute it directly", !File(ws, "works").exists())
    r = CloudClient.chat(ctx, "/list_files path=extensions", emptyList())
    check("/tool direct command", r.startsWith("[list_files]") && r.contains("helloworld"), r)

    println(if (fails == 0) "\nE2E ALL PASSED" else "\n$fails FAILED")
}
