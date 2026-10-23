package com.nine.dbt

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Light-shell copy of NINE's GuestRuntime — same FQCN so the JNI symbol
 * names (Java_com_nine_dbt_GuestRuntime_*) bind unchanged against the
 * shared libnexus_core.so shipped in the shell APK's lib/arm64-v8a.
 *
 * Hop (loadAndRunAsync) is not carried over; the shell module has no
 * coroutines dependency and the shell drives runs on its own thread.
 */

/** One library resolved by a relink (see nativeRelink JSON contract). */
data class RelinkLibrary(
    val name: String,
    val provider: String,    // "bundled" | "nine-abi"
    val path: String,
    val installPath: String  // guest path: "/usr/lib" | "C:\Windows\System32"
)

/** Parsed nativeRelink JSON result. */
data class RelinkResult(
    val ok: Boolean,
    val os: String,
    val summary: String,
    val error: String,
    val libraries: List<RelinkLibrary>,
    val unresolved: List<String>
) {
    companion object {
        fun parse(raw: String): RelinkResult = try {
            val o = JSONObject(raw.trim())
            RelinkResult(
                ok = o.optBoolean("ok", false),
                os = o.optString("os", ""),
                summary = o.optString("summary", ""),
                error = o.optString("error", ""),
                libraries = runCatching {
                    val arr = o.optJSONArray("libraries") ?: JSONArray()
                    (0 until arr.length()).map { i ->
                        val l = arr.getJSONObject(i)
                        RelinkLibrary(
                            name = l.optString("name", ""),
                            provider = l.optString("provider", ""),
                            path = l.optString("path", ""),
                            installPath = l.optString("installPath", "")
                        )
                    }
                }.getOrDefault(emptyList()),
                unresolved = runCatching {
                    val arr = o.optJSONArray("unresolved") ?: JSONArray()
                    (0 until arr.length()).map { i -> arr.getString(i) }
                }.getOrDefault(emptyList())
            )
        } catch (e: Throwable) {
            RelinkResult(
                ok = false, os = "", summary = "",
                error = "unparseable relink output: ${raw.take(300)}",
                libraries = emptyList(), unresolved = emptyList()
            )
        }
    }
}

/** UI/runtime bridge to the native load/execute path (shared with NINE). */
object GuestRuntime {
    init {
        try {
            System.loadLibrary("nexus_core")
            // Wire the native Logger sink → GuestLog.onNativeLine so every
            // native log line lands on the shell's log file from startup.
            nativeInit()
        } catch (_: Throwable) {
        }
    }

    @Volatile
    var lastStatus: String = ""
        private set

    @Volatile
    var isRunning: Boolean = false
        private set

    fun loadAndRunBlocking(path: String, cacheDir: File): String {
        isRunning = true
        return try {
            val r = nativeLoadAndRun(path, cacheDir.absolutePath)
            lastStatus = r
            r
        } catch (e: Throwable) {
            val m = "load failed: ${e.message}"
            lastStatus = m
            GuestLog.add(m)
            m
        } finally {
            isRunning = false
            lastStatus = nativeStatus()
        }
    }

    fun stop() = try { nativeStop() } catch (_: Throwable) {}
    fun pause() = try { nativePause() } catch (_: Throwable) {}
    fun resume() = try { nativeResume() } catch (_: Throwable) {}
    fun step() = try { nativeStep() } catch (_: Throwable) {}
    fun setBreakpoint(pc: Long) = try { nativeSetBreakpoint(pc) } catch (_: Throwable) {}
    fun clearBreakpoints() = try { nativeClearBreakpoints() } catch (_: Throwable) {}

    fun status(): String = try {
        nativeStatus().also { lastStatus = it }
    } catch (e: Throwable) {
        e.message ?: "status unavailable"
    }

    /** Relink a stored program against NINE's ABI without executing it. */
    fun relink(path: String, libDirs: List<String>): String = try {
        nativeRelink(path, libDirs.joinToString(":")).also { lastStatus = it }
    } catch (e: Throwable) {
        val m = "relink failed: ${e.message}"
        lastStatus = m
        GuestLog.add(m)
        m
    }

    fun relinkResult(path: String, libDirs: List<String>): RelinkResult = try {
        RelinkResult.parse(relink(path, libDirs))
    } catch (e: Throwable) {
        RelinkResult(
            ok = false, os = "", summary = "",
            error = e.message ?: "relink failed",
            libraries = emptyList(), unresolved = emptyList()
        )
    }

    // ---------- DLSS-style upscaler / game detection surface ----------

    fun detectGame(path: String): String = try {
        nativeDetectGame(path)
    } catch (e: Throwable) {
        "{\"isGame\":false,\"score\":0,\"os\":\"\",\"reasons\":[\"detector failed: ${e.message}\"]}"
    }

    fun setUpscalerModel(dir: String): String = try {
        nativeUpscalerSetModel(dir)
    } catch (e: Throwable) {
        "{\"enabled\":false,\"error\":\"model import failed: ${e.message}\"}"
    }

    fun upscalerStatus(): String = try {
        nativeUpscalerStatus()
    } catch (e: Throwable) {
        "{\"enabled\":false}"
    }

    fun setUpscalerEnabled(v: Boolean) = try {
        nativeUpscalerSetEnabled(v)
    } catch (_: Throwable) {
    }

    private external fun nativeInit()
    private external fun nativeLoadAndRun(path: String, cacheDir: String): String
    private external fun nativeRelink(path: String, libDirs: String): String
    private external fun nativeStop()
    private external fun nativePause()
    private external fun nativeResume()
    private external fun nativeStep()
    private external fun nativeSetBreakpoint(pc: Long)
    private external fun nativeClearBreakpoints()
    private external fun nativeStatus(): String
    private external fun nativeDetectGame(path: String): String
    private external fun nativeUpscalerSetModel(dir: String): String
    private external fun nativeUpscalerStatus(): String
    private external fun nativeUpscalerSetEnabled(v: Boolean)
}
