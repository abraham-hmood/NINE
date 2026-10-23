package com.nine.shell

import android.app.Activity
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.io.File

/**
 * Light-shell settings — same DLSS checkbox + model folder button as NINE's,
 * plus the program-log viewer button and the VHD path the program uses.
 * The image-upscaler button is greyed out/disabled while the DLSS switch is
 * off (visible either way), enabled when it's on.
 */
class ShellSettingsActivity : Activity() {

    private val RC_IMPORT_UPSCALER = 9001

    private fun launchUpscalerPicker() {
        val intent = android.content.Intent(android.content.Intent.ACTION_OPEN_DOCUMENT_TREE)
        startActivityForResult(intent, RC_IMPORT_UPSCALER)
    }

    private lateinit var dlssSwitch: Switch
    private lateinit var importBtn: Button
    private lateinit var modelStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            setBackgroundColor(Color.BLACK)
        }

        val title = TextView(this).apply {
            text = "SETTINGS"
            setTextColor(Color.CYAN)
            textSize = 22f
        }
        col.addView(title)

        fun row(content: android.view.View) {
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            lp.topMargin = 40
            col.addView(content, lp)
        }

        // DLSS switch
        dlssSwitch = Switch(this).apply {
            text = "DLSS-style upscaling for games"
            setTextColor(Color.WHITE)
        }
        row(dlssSwitch)
        val dlssHint = TextView(this).apply {
            text = "Applies image upscaling to programs detected as games"
            setTextColor(Color.LTGRAY); textSize = 11f
        }
        row(dlssHint)

        // import button (greyed while switch off)
        importBtn = Button(this).apply {
            text = "IMPORT IMAGE UPSCALER MODEL (folder)"
            textSize = 12f
            setOnClickListener { launchUpscalerPicker() }
        }
        row(importBtn)
        modelStatus = TextView(this).apply {
            setTextColor(Color.LTGRAY); textSize = 11f
        }
        row(modelStatus)

        // logs button
        row(Button(this).apply {
            text = "LOGS"
            setOnClickListener {
                startActivity(android.content.Intent(this@ShellSettingsActivity, ShellLogsActivity::class.java))
            }
        })

        // VHD path (read from the payload added at packaging time)
        val vhdPath = readVhdPath()
        row(TextView(this).apply {
            text = "VIRTUAL HARD DISK\n${if (vhdPath.isEmpty()) "(none set — relink this program in NINE)" else vhdPath}"
            setTextColor(Color.WHITE); textSize = 13f
        })

        // back
        row(Button(this).apply {
            text = "DONE"
            setOnClickListener { finish() }
        })

        dlssSwitch.setOnCheckedChangeListener { _, checked ->
            ShellPrefs.setDlssEnabled(this, checked)
            refreshStates()
            try {
                com.nine.dbt.GuestRuntime.setUpscalerEnabled(checked)
            } catch (_: Throwable) {}
        }

        setContentView(ScrollView(this).apply {
            addView(col, android.view.ViewGroup.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT))
        })
        refreshStates()
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
            !on -> "enable DLSS-style upscaling to import a model"
            hasModel -> "model: ${dir.listFiles()?.joinToString { it.name }} (imported)"
            else -> "no upscaler model imported yet"
        }
        applyEnabled()
    }

    private fun readVhdPath(): String = try {
        assets.open("vhd_path.txt").bufferedReader().readText().trim()
    } catch (_: Throwable) { "" }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != RC_IMPORT_UPSCALER || resultCode != RESULT_OK) return
        val tree = data?.data ?: return
        try {
            contentResolver.takePersistableUriPermission(
                tree, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (_: Exception) {}
        Thread {
            val res = runCatching { copyTree(tree) }
            if (res.isSuccess) {
                val dir = res.getOrThrow()
                val status = com.nine.dbt.GuestRuntime.setUpscalerModel(dir.absolutePath)
                runOnUiThread { modelStatus.text = "upscaler: $status" }
            } else {
                val msg = "import failed: ${res.exceptionOrNull()?.message}"
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
            tree, DocumentsContract.getTreeDocumentId(tree))
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
                val name = it.getString(1) ?: continue
                val mime = it.getString(2) ?: ""
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) continue
                val docUri = DocumentsContract.buildDocumentUriUsingTree(tree, docId)
                val dest = File(dir, name)
                contentResolver.openInputStream(docUri)?.use { input ->
                    dest.outputStream().use { input.copyTo(it) }
                }
            }
        }
        return dir
    }
}
