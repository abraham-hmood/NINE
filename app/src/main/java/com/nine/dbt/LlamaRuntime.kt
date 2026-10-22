package com.nine.dbt

object LlamaRuntime {
    init {
        try { System.loadLibrary("nexus_core") } catch (_: UnsatisfiedLinkError) {}
    }

    fun available(): Boolean = try { nativeAvailable() } catch (_: UnsatisfiedLinkError) { false }
    fun load(path: String): String = try { nativeLoad(path) } catch (e: UnsatisfiedLinkError) { e.message ?: "link error" }
    fun generate(prompt: String, maxTokens: Int = 128): String =
        try { nativeGenerate(prompt, maxTokens) } catch (e: UnsatisfiedLinkError) { e.message ?: "link error" }
    fun free() { try { nativeFree() } catch (_: UnsatisfiedLinkError) {} }

    private external fun nativeAvailable(): Boolean
    private external fun nativeLoad(path: String): String
    private external fun nativeGenerate(prompt: String, maxTokens: Int): String
    private external fun nativeFree()
}
