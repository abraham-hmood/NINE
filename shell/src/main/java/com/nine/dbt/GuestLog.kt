package com.nine.dbt

import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Light-shell GuestLog — same FQCN and JNI surface as NINE's
 * (com/nine/dbt/GuestLog with static `add` / `onNativeLine`), so the native
 * Logger sink in libnexus_core binds unchanged.
 *
 * Two differences from NINE's copy:
 *   - no Compose state (shell module has no compose dependency)
 *   - every line is ALSO appended to filesDir/guest-logs/session.log, which
 *     is exactly what ShellLogsActivity displays (same content as NINE's
 *     Logs tab for a session).
 */
object GuestLog {
    val lines = CopyOnWriteArrayList<String>()
    private val lock = Any()

    @JvmStatic
    fun add(msg: String) {
        append(msg)
        AppLog.e("guest", msg)
    }

    fun info(msg: String) {
        append(msg)
        AppLog.i("guest", msg)
    }

    /** Sink target for native code (libnexus_core Logger → nativeInit). */
    @JvmStatic
    fun onNativeLine(line: String) {
        append(line)
        AppLog.i("native", line)
    }

    private fun append(msg: String) {
        lines.add(0, msg)
        if (lines.size > 2000) lines.subList(1500, lines.size).clear()
        synchronized(lock) {
            try {
                val dir = File(filesDirOrNull() ?: return, "guest-logs")
                dir.mkdirs()
                val ts = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
                FileOutputStream(File(dir, "session.log"), true).use {
                    it.write("[$ts] $msg\n".toByteArray(Charsets.UTF_8))
                }
            } catch (_: Throwable) {
            }
        }
    }

    // set lazily by the shell Application/activity so we can log from any context
    @Volatile
    private var appDir: File? = null

    fun initFileLog(filesDir: File) {
        appDir = filesDir
    }

    private fun filesDirOrNull(): File? = appDir
}
