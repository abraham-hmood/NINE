package com.nine.dbt
import android.content.Context
object AppLog { fun d(a:String,b:String){} ; fun i(a:String,b:String){}; fun w(a:String,b:String){ println("LOG w: $b") }; fun e(a:String,b:String,t:Throwable?=null){ println("LOG e: $b $t") } }
object AppStore {
    var url = ""
    val tools = mutableListOf<AgenticTool>()
    fun customTools(ctx: Context): MutableList<AgenticTool> = tools
    fun saveCustomTools(ctx: Context, t: List<AgenticTool>) { }
    fun useLocal(ctx: Context) = false
    fun activeCloud(ctx: Context): CloudModel? = CloudModel(url, "test-model", url, "key")
}
object ExtensionInstaller {
    fun installApk(ctx: Context, apk: java.io.File) { println("STUB install ${apk.name} (${apk.length()} bytes)") }
    fun applyPatch(ctx: Context, patch: java.io.File, base: String) = base
}
object LocalAiEngine { fun chat(ctx: Context, turns: List<Pair<String,String>>) = "" }
