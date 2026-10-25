package com.nine.shell

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.io.File

/**
 * Light-shell settings — NINE's DLSS switch + model folder import, the program
 * log viewer and the VHD path the program uses, laid out in NINE's card style.
 * The image-upscaler import stays visible but disabled while DLSS is off.
 */
class ShellSettingsActivity : Activity() {

    private val RC_IMPORT_UPSCALER = 9001

    private fun launchUpscalerPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
        startActivityForResult(intent, RC_IMPORT_UPSCALER)
    }

    private lateinit var dlssSwitch: Switch
    private lateinit var importBtn: Button
    private lateinit var modelStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = ShellTheme.BG
        window.navigationBarColor = ShellTheme.BG

        val px = { dp: Int -> ShellTheme.px(this, dp) }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(20), px(24), px(20), px(24))
            setBackgroundColor(ShellTheme.BG)
        }

        val name = try {
            applicationInfo.loadLabel(packageManager).toString()
        } catch (_: Throwable) {
            "Program"
        }
        col.addView(ShellTheme.header(this, "SETTINGS", "NINE · LIGHT SHELL · $name"))
        col.addView(gap(px(18)))

        // ---- RENDER ----
        val render = ShellTheme.card(this)
        render.addView(ShellTheme.label(this, "RENDER"))
        dlssSwitch = Switch(this).apply {
            text = "DLSS-style upscaling for games"
            setTextColor(ShellTheme.TEXT)
            textSize = 14f
            setPadding(0, px(8), 0, 0)
            thumbTintList = ShellTheme.switchTint(this@ShellSettingsActivity)
            trackTintList = ShellTheme.trackTint(this@ShellSettingsActivity)
        }
        render.addView(dlssSwitch)
        render.addView(ShellTheme.body(
            this,
            "Applies NINE's edge-adaptive upscaler to programs detected as games.",
            ShellTheme.MUTED,
            11f
        ))
        render.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(12)))
        render.addView(ShellTheme.divider(this))
        render.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(12)))
        importBtn = ShellTheme.secondaryButton(this, "IMPORT IMAGE UPSCALER MODEL") {
            launchUpscalerPicker()
        }
        render.addView(importBtn, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ))
        modelStatus = ShellTheme.body(this, "", ShellTheme.MUTED, 11f).apply {
            setPadding(0, px(8), 0, 0)
        }
        render.addView(modelStatus)
        col.addView(render)

        // ---- PROGRAM ----
        col.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(14)))
        val program = ShellTheme.card(this)
        program.addView(ShellTheme.label(this, "PROGRAM"))
        program.addView(ShellTheme.body(this, name, ShellTheme.TEXT, 15f).apply {
            setPadding(0, px(6), 0, 0)
        })
        program.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(10)))
        program.addView(ShellTheme.divider(this))
        program.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(10)))
        program.addView(ShellTheme.label(this, "VIRTUAL HARD DISK"))
        val vhdPath = readVhdPath()
        program.addView(ShellTheme.body(
            this,
            if (vhdPath.isEmpty()) "(none set — relink this program in NINE)" else vhdPath,
            if (vhdPath.isEmpty()) ShellTheme.MUTED else ShellTheme.CYAN_SOFT,
            12f
        ).apply { setPadding(0, px(6), 0, 0) })
        col.addView(program)

        // ---- DIAGNOSTICS ----
        col.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(14)))
        val diag = ShellTheme.card(this)
        diag.addView(ShellTheme.label(this, "DIAGNOSTICS"))
        diag.addView(ShellTheme.body(
            this,
            "The session log is the same stream NINE's Logs tab shows, including " +
                "guest stdout/stderr.",
            ShellTheme.MUTED,
            11f
        ).apply { setPadding(0, px(6), 0, 0) })
        diag.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(12)))
        diag.addView(ShellTheme.purpleButton(this, "OPEN SESSION LOG") {
            startActivity(Intent(this@ShellSettingsActivity, ShellLogsActivity::class.java))
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ))
        col.addView(diag)

        col.addView(gap(ViewGroup.LayoutParams.MATCH_PARENT, px(18)))
        col.addView(ShellTheme.primaryButton(this, "DONE") { finish() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ))

        setContentView(ScrollView(this).apply {
            setBackgroundColor(ShellTheme.BG)
            addView(col, ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ))
        })

        dlssSwitch.setOnCheckedChangeListener { _, checked ->
            ShellPrefs.setDlssEnabled(this, checked)
            refreshStates()
            try {
                com.nine.dbt.GuestRuntime.setUpscalerEnabled(checked)
            } catch (_: Throwable) {
            }
        }
        refreshStates()
    }

    private fun gap(height: Int): android.view.View =
        gap(ViewGroup.LayoutParams.MATCH_PARENT, height)

    private fun gap(width: Int, height: Int): android.view.View =
        android.view.View(this).apply {
            layoutParams = LinearLayout.LayoutParams(width, height)
        }

    private fun applyEnabled() {
        val on = ShellPrefs.dlssEnabled(this)
        dlssSwitch.isChecked = on
        importBtn.isEnabled = on
        importBtn.alpha = if (on) 1.0f else 0.4f
    }

    private fun refreshStates() {
        val on = ShellPrefs.dlssEnabled(this)
        val dir = File(filesDir, "upscaler/model")
        val hasModel = dir.isDirectory && dir.listFiles()?.isNotEmpty() == true
        modelStatus.text = when {
            !on -> "Enable DLSS-style upscaling to import a model."
            hasModel -> "Model: ${dir.listFiles()?.joinToString { it.name }} (imported)"
            else -> "No upscaler model imported yet."
        }
        applyEnabled()
    }

    private fun readVhdPath(): String = try {
        assets.open("vhd_path.txt").bufferedReader().readText().trim()
    } catch (_: Throwable) {
        ""
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != RC_IMPORT_UPSCALER || resultCode != RESULT_OK) return
        val tree = data?.data ?: return
        try {
            contentResolver.takePersistableUriPermission(
                tree, Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (_: Exception) {
        }
        Thread {
            val res = runCatching { copyTree(tree) }
            if (res.isSuccess) {
                val dir = res.getOrThrow()
                val status = com.nine.dbt.GuestRuntime.setUpscalerModel(dir.absolutePath)
                runOnUiThread { modelStatus.text = "Upscaler: $status" }
            } else {
                val msg = "Import failed: ${res.exceptionOrNull()?.message}"
                runOnUiThread {
                    Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
                    modelStatus.text = msg
                }
            }
        }.start()
    }

    private fun copyTree(tree: Uri): File {
        val dir = File(filesDir, "upscaler/model").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val root = DocumentsContract.buildChildDocumentsUriUsingTree(
            tree, DocumentsContract.getTreeDocumentId(tree)
        )
        val cursor = contentResolver.query(
            root,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE
            ),
            null, null, null
        ) ?: throw IllegalStateException("folder unreadable")
        cursor.use {
            while (it.moveToNext()) {
                val docId = it.getString(0) ?: continue
                val fileName = it.getString(1) ?: continue
                val mime = it.getString(2) ?: ""
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) continue
                val docUri = DocumentsContract.buildDocumentUriUsingTree(tree, docId)
                val dest = File(dir, fileName)
                contentResolver.openInputStream(docUri)?.use { input ->
                    dest.outputStream().use { input.copyTo(it) }
                }
            }
        }
        return dir
    }
}
