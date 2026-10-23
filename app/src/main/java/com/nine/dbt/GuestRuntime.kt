package com.nine.dbt

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

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

/**
 * J5: UI bridge to the native load/execute path.
 * Never call [loadAndRunBlocking] on the main thread for large programs —
 * use [loadAndRunAsync] instead.
 */
object GuestRuntime {
    init {
        try {
            System.loadLibrary("nexus_core")
            // Wire the native Logger sink → GuestLog.onNativeLine so every
            // native log line (loader, translator, ABI, guest stdout…) lands
            // on the Logs tab from startup onward.
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

    suspend fun loadAndRunAsync(path: String, cacheDir: File): String =
        withContext(Dispatchers.IO) {
            loadAndRunBlocking(path, cacheDir)
        }

    fun stop() = try {
        nativeStop()
    } catch (_: Throwable) {
    }

    fun pause() = try {
        nativePause()
    } catch (_: Throwable) {
    }

    fun resume() = try {
        nativeResume()
    } catch (_: Throwable) {
    }

    fun step() = try {
        nativeStep()
    } catch (_: Throwable) {
    }

    fun setBreakpoint(pc: Long) = try {
        nativeSetBreakpoint(pc)
    } catch (_: Throwable) {
    }

    fun clearBreakpoints() = try {
        nativeClearBreakpoints()
    } catch (_: Throwable) {
    }

    fun status(): String = try {
        nativeStatus().also { lastStatus = it }
    } catch (e: Throwable) {
        e.message ?: "status unavailable"
    }

    /**
     * Relink a stored program against NINE's ABI without executing it.
     * [libDirs] are the program's expected library directories (from config.json);
     * DT_NEEDED/imported symbols resolve to bundled libs or NINE's shims.
     * Safe to call off the main thread (native work is blocking).
     * Returns the native JSON string (see [relinkResult]).
     */
    fun relink(path: String, libDirs: List<String>): String = try {
        nativeRelink(path, libDirs.joinToString(":")).also { lastStatus = it }
    } catch (e: Throwable) {
        val m = "relink failed: ${e.message}"
        lastStatus = m
        GuestLog.add(m)
        m
    }

    /**
     * Relink and parse the structured JSON result: resolved libraries with
     * their providers and guest install paths, plus anything unresolved.
     * Never throws — failures come back as `ok=false` with an error message.
     */
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

    /**
     * Heuristic game detection for a stored program binary.
     * Returns native JSON: {"isGame":..,"score":..,"os":..,"reasons":[..]}
     */
    fun detectGame(path: String): String = try {
        nativeDetectGame(path)
    } catch (e: Throwable) {
        "{\"isGame\":false,\"score\":0,\"os\":\"\",\"reasons\":[\"detector failed: ${e.message}\"]}"
    }

    /**
     * Import an image-upscale model. [dir] is the app-side folder the user's
     * picked tree was copied into. Returns the upscaler status JSON.
     */
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
