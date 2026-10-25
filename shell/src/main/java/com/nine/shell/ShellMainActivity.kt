package com.nine.shell

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import com.nine.dbt.GuestLog
import com.nine.dbt.GuestRuntime

/**
 * Light shell main activity.
 *
 * - full-bleed [SurfaceView] where the program's GUI is rendered (framebuffer
 *   pipeline now: guests without GUI output simply run head-less here)
 * - NINE-styled header (9 mark, program name, status card) and a settings
 *   button opening [ShellSettingsActivity]
 * - on start: extracts the packaged payload and runs the executable through
 *   libnexus_core (shared ABI with NINE)
 */
class ShellMainActivity : Activity() {

    private val running = AtomicBoolean(false)
    private var programName = "Program"
    private lateinit var statusValue: TextView
    private lateinit var statusHint: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.statusBarColor = ShellTheme.BG
        window.navigationBarColor = ShellTheme.BG

        programName = try {
            applicationInfo.loadLabel(packageManager).toString()
        } catch (_: Throwable) {
            "Program"
        }

        val root = FrameLayout(this).apply { setBackgroundColor(ShellTheme.BG) }

        val surface = SurfaceView(this)
        surface.holder.addCallback(object : SurfaceHolder.Callback {
            override fun surfaceCreated(holder: SurfaceHolder) {}
            override fun surfaceChanged(h: SurfaceHolder, f: Int, w: Int, hh: Int) {}
            override fun surfaceDestroyed(h: SurfaceHolder) {}
        })
        root.addView(surface, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))

        val px = { dp: Int -> ShellTheme.px(this, dp) }
        val overlay = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(20), px(20), px(20), px(20))
            fitsSystemWindows = true
        }

        overlay.addView(ShellTheme.header(this, programName, "NINE · LIGHT SHELL"))
        overlay.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(18)))

        // ---- status card ----
        val statusCard = ShellTheme.card(this)
        statusCard.addView(ShellTheme.label(this, "STATUS"))
        statusValue = ShellTheme.heading(this, "STARTING", 20f).apply {
            setPadding(0, px(6), 0, 0)
        }
        statusCard.addView(statusValue)
        statusHint = ShellTheme.body(
            this,
            "Extracting the packaged program…",
            ShellTheme.MUTED,
            12f
        ).apply { setPadding(0, px(6), 0, 0) }
        statusCard.addView(statusHint)
        statusCard.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(10)))
        statusCard.addView(ShellTheme.divider(this))
        statusCard.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(10)))
        statusCard.addView(ShellTheme.body(
            this,
            "The guest runs on NINE's own x86-64 translator; the SurfaceView is " +
                "the framebuffer target once the GUI pipeline lands.",
            ShellTheme.CYAN_SOFT,
            11f
        ))
        overlay.addView(statusCard, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ))

        overlay.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        // ---- actions ----
        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        actions.addView(ShellTheme.secondaryButton(this, "⚙  SETTINGS") {
            startActivity(Intent(this@ShellMainActivity, ShellSettingsActivity::class.java))
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(gap(px(10), ViewGroup.LayoutParams.MATCH_PARENT))
        actions.addView(ShellTheme.purpleButton(this, "SESSION LOG") {
            startActivity(Intent(this@ShellMainActivity, ShellLogsActivity::class.java))
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        overlay.addView(actions)

        root.addView(overlay, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        setContentView(root)

        // enable the file-backed session log before anything logs
        GuestLog.initFileLog(filesDir)

        thread(name = "shell-run") {
            try {
                val exec = ShellPayload.extractAndPrepare(this)
                runOnUiThread {
                    statusValue.text = "RUNNING"
                    statusValue.setTextColor(ShellTheme.CYAN)
                    statusHint.text = exec.relativeToOrSelf(filesDir).path
                }
                GuestLog.info("shell: launching ${exec.absolutePath}")
                GuestRuntime.setUpscalerEnabled(ShellPrefs.dlssEnabled(this))
                val upscalerDir = File(filesDir, "upscaler/model")
                if (upscalerDir.exists()) {
                    GuestRuntime.setUpscalerModel(upscalerDir.absolutePath)
                }
                val result = GuestRuntime.loadAndRunBlocking(exec.absolutePath, cacheDir)
                GuestLog.info("shell: run finished: ${result.take(400)}")
                runOnUiThread {
                    statusValue.text = "EXITED"
                    statusValue.setTextColor(ShellTheme.CYAN_SOFT)
                    statusHint.text = result.take(220)
                }
            } catch (t: Throwable) {
                GuestLog.add("shell: launch failed: ${t.message}")
                runOnUiThread {
                    statusValue.text = "FAILED"
                    statusValue.setTextColor(0xFFFF5252.toInt())
                    statusHint.text = t.message ?: "unknown error"
                    Toast.makeText(this, t.message, Toast.LENGTH_LONG).show()
                }
            } finally {
                running.set(false)
            }
        }
    }

    private fun gap(width: Int, height: Int, weight: Float = 0f): android.view.View =
        android.view.View(this).apply {
            layoutParams = LinearLayout.LayoutParams(width, height, weight)
        }
}

/** Preferences object mirroring NINE's light-shell-relevant settings. */
object ShellPrefs {
    private val PREFS = "shell_settings"

    fun dlssEnabled(ctx: android.content.Context): Boolean =
        ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            .getBoolean("enable_dlss", false)

    fun setDlssEnabled(ctx: android.content.Context, v: Boolean) {
        ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE).edit()
            .putBoolean("enable_dlss", v).apply()
    }
}

/**
 * Extracts the packaged program payload.
 *
 * Every guest binary is mirrored by the packager as `lib/<abi>/libnine_<n>.so`
 * (see LightShellPackager), because Android drops or refuses payload files that
 * are not part of the native-library surface. Those mirrored copies are
 * extracted by the package manager into `nativeLibraryDir`, so the shell reads
 * them from there and only falls back to the assets copy when a slot is
 * missing. `payload.json` maps each slot back to the program's real path.
 */
object ShellPayload {

    fun extractAndPrepare(activity: Activity): File {
        val outDir = File(activity.filesDir, "program")
        outDir.deleteRecursively()
        outDir.mkdirs()
        val nativeDir = File(activity.applicationInfo.nativeLibraryDir)
        val manifest = readManifest(activity)
        var execRel: String? = null

        if (manifest != null) {
            execRel = manifest.optString("exec").takeIf { it.isNotBlank() }
            val files = manifest.optJSONArray("files") ?: JSONArray()
            for (i in 0 until files.length()) {
                val entry = files.optJSONObject(i) ?: continue
                val rel = entry.optString("rel")
                if (rel.isBlank()) continue
                val dest = resolveInside(outDir, rel) ?: continue
                dest.parentFile?.mkdirs()
                val slot = entry.optString("slot")
                val persisted = if (slot.isBlank()) null else File(nativeDir, slot)
                if (persisted != null && persisted.isFile) {
                    // preferred: the installer-extracted .so mirror
                    persisted.inputStream().use { input ->
                        dest.outputStream().use { input.copyTo(it) }
                    }
                } else {
                    copyAsset(activity, "program/$rel", dest)
                }
            }
        } else {
            // Legacy shells (no payload.json): walk the assets tree.
            walkAssets(activity, outDir, "program")
        }

        // Small text payloads always come from assets.
        copyAsset(activity, "program/config.json", File(outDir, "config.json"))
        copyAsset(activity, "program/execRel.txt", File(outDir, "execRel.txt"))

        if (execRel.isNullOrBlank()) {
            execRel = File(outDir, "execRel.txt").takeIf { it.isFile }?.readText()?.trim()
        }
        val exec = execRel?.let { resolveInside(outDir, it) }
            ?: throw IllegalStateException("payload manifest has no executable")
        if (!exec.isFile) throw IllegalStateException("payload exec missing: $execRel")
        exec.setReadable(true, true)
        return exec
    }

    private fun readManifest(activity: Activity): JSONObject? = try {
        activity.assets.open("program/payload.json").bufferedReader().use { reader ->
            JSONObject(reader.readText())
        }
    } catch (_: Throwable) {
        null
    }

    /** Canonicalises [rel] under [root]; null when it would escape the payload dir. */
    private fun resolveInside(root: File, rel: String): File? {
        val dest = File(root, rel)
        val rootPath = root.canonicalPath + File.separator
        return if (dest.canonicalPath.startsWith(rootPath)) dest else null
    }

    private fun copyAsset(activity: Activity, assetPath: String, dest: File) {
        try {
            dest.parentFile?.mkdirs()
            activity.assets.open(assetPath).use { input: InputStream ->
                dest.outputStream().use { input.copyTo(it) }
            }
        } catch (_: Throwable) {
            // optional payload entry (config.json may legitimately be absent)
        }
    }

    private fun walkAssets(activity: Activity, outDir: File, path: String) {
        val am = activity.assets
        am.list(path)?.forEach { child ->
            val full = if (path.isEmpty()) child else "$path/$child"
            if (am.list(full)?.isNotEmpty() == true) {
                walkAssets(activity, outDir, full)
            } else {
                val rel = full.removePrefix("program/")
                val dest = resolveInside(outDir, rel) ?: return@forEach
                copyAsset(activity, full, dest)
            }
        }
    }
}
