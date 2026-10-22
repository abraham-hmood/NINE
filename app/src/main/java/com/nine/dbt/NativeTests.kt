package com.nine.dbt

object NativeTests {
    init { try { System.loadLibrary("nexus_core") } catch (_: Throwable) {} }
    external fun run(id: String): String
}
