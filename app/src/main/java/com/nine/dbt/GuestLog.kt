package com.nine.dbt

import androidx.compose.runtime.mutableStateListOf

object GuestLog {
    val lines = mutableStateListOf<String>()

    @JvmStatic
    fun add(msg: String) {
        lines.add(0, msg)
        AppLog.e("guest", msg)
    }

    fun info(msg: String) {
        lines.add(0, msg)
        AppLog.i("guest", msg)
    }

    /**
     * Sink target for native code (libnexus_core Logger → nativeInit).
     * Called from any thread, including DBT worker threads.
     * JNI: static "(Ljava/lang/String;)V" on com/nine/dbt/GuestLog.
     */
    @JvmStatic
    fun onNativeLine(line: String) {
        lines.add(0, line)
        AppLog.i("native", line)
    }
}
