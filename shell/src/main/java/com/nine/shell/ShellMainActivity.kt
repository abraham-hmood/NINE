package com.nine.shell

import android.app.Activity
import android.content.DialogInterface
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.ViewGroup
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
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
 * - floating "⚙" settings button top-right → [ShellSettingsActivity]
 * - on start: extracts "assets/program" entries into filesDir and runs the
 *   executable through libnexus_core (shared ABI with NINE)
 */
class ShellMainActivity : Activity() {

    private val running = AtomicBoolean(false)
    private var programName = "Program"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }

        val surface = SurfaceView(this)
        surface.holder.addCallback(object : SurfaceHolder.Callback {
            override fun surfaceCreated(holder: SurfaceHolder) {}
            override fun surfaceChanged(h: SurfaceHolder, f: Int, w: Int, hh: Int) {}
            override fun surfaceDestroyed(h: SurfaceHolder) {}
        })
        root.addView(surface, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))

        val settings = Button(this).apply {
            text = "⚙"
            textSize = 22f
            setTextColor(Color.WHITE)
            setBackgroundColor(0x66000000)
            setOnClickListener { startActivity(android.content.Intent(this@ShellMainActivity, ShellSettingsActivity::class.java)) }
        }
        root.addView(settings, FrameLayout.LayoutParams(
            120, 120, Gravity.TOP or Gravity.END).apply {
            setMargins(16, 16, 16, 16)
        })

        val banner = TextView(this).apply {
            text = "GUI render pipeline pending — program runs head-less.\nLogs live in Settings › LOGS."
            setTextColor(Color.LTGRAY)
            textSize = 13f
            gravity = Gravity.CENTER
            setPadding(24, 24, 24, 24)
        }
        root.addView(banner, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM))
        setContentView(root)

        // enable the file-backed session log before anything logs
        com.nine.dbt.GuestLog.initFileLog(filesDir)

        thread(name = "shell-run") {
            try {
                val exec = ShellPayload.extractAndPrepare(this)
                programName = exec.name
                GuestLog.info("shell: launching ${exec.absolutePath}")
                GuestRuntime.setUpscalerEnabled(ShellPrefs.dlssEnabled(this))
                val upscalerDir = File(filesDir, "upscaler/model")
                if (upscalerDir.exists()) {
                    GuestRuntime.setUpscalerModel(upscalerDir.absolutePath)
                }
                val result = GuestRuntime.loadAndRunBlocking(exec.absolutePath, cacheDir)
                GuestLog.info("shell: run finished: ${result.take(400)}")
            } catch (t: Throwable) {
                GuestLog.add("shell: launch failed: ${t.message}")
                runOnUiThread {
                    Toast.makeText(this, t.message, Toast.LENGTH_LONG).show()
                }
            } finally {
                running.set(false)
            }
        }
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

/** Extracts the packaged program payload from the shell APK's assets. */
object ShellPayload {
    fun extractAndPrepare(activity: Activity): File {
        val outDir = File(activity.filesDir, "program").apply { deleteRecursively(); mkdirs() }
        val am = activity.assets
        fun walk(path: String) {
            am.list(path)?.forEach { child ->
                val full = if (path.isEmpty()) child else "$path/$child"
                if (am.list(full)?.isNotEmpty() == true) {
                    walk(full)
                } else {
                    val dest = File(outDir, full.removePrefix("program/"))
                    dest.parentFile?.mkdirs()
                    am.open(full).use { input: InputStream ->
                        dest.outputStream().use { input.copyTo(it) }
                    }
                }
            }
        }
        walk("program")

        val execRel = File(outDir, "execRel.txt").readText().trim()
        val exec = File(outDir, execRel)
        if (!exec.exists()) throw IllegalStateException("payload exec missing: $execRel")
        return exec
    }
}
