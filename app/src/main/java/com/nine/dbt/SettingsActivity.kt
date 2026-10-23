package com.nine.dbt

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.File

class SettingsActivity : ComponentActivity() {
    private val importLlm = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri?.let {
            try {
                contentResolver.takePersistableUriPermission(it, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            } catch (_: Exception) {}
            AppStore.setLocalModelUri(this, it.toString())
        }
    }
    private val importUpscaler = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        uri?.let { tree ->
            try {
                contentResolver.takePersistableUriPermission(
                    tree, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            } catch (_: Exception) {}
            lifecycleScope.launch(Dispatchers.IO) {
                val res = runCatching { importUpscalerModel(tree) }
                res.onSuccess { dir ->
                    AppStore.setUpscalerModelDir(this@SettingsActivity, dir.absolutePath)
                    GuestLog.info("upscaler model imported from $tree -> ${dir.absolutePath}")
                    val st = GuestRuntime.setUpscalerModel(dir.absolutePath)
                    upscalerStatus = GuestRuntime.upscalerStatus()
                    GuestLog.info("upscaler status: $st")
                }.onFailure {
                    GuestLog.add("upscaler import failed: ${it.message}")
                }
            }
        }
    }

    private var upscalerStatus by mutableStateOf("{}")

    /** Copies every file from the user's picked tree into filesDir/upscaler/model. */
    private fun importUpscalerModel(tree: Uri): File {
        val dir = File(filesDir, "upscaler/model").apply { mkdirs() }
        // wipe previous import so the newest folder is authoritative
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
        var copied = 0
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
                copied++
            }
        }
        GuestLog.info("upscaler import: copied $copied file(s) into ${dir.absolutePath}")
        return dir
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NineTheme {
                var useLocal by remember { mutableStateOf(AppStore.useLocal(this)) }
                var enableDlss by remember { mutableStateOf(AppStore.enableDlss(this)) }
                var showImport by remember { mutableStateOf(false) }
                val imported = AppStore.localModels(this)
                val modelStatus = remember(enableDlss) {
                    GuestRuntime.upscalerStatus().takeIf { it != "{\"enabled\":false}" } ?: ""
                }
                SettingsScreen(
                    useLocal = useLocal,
                    onUseLocalChange = {
                        useLocal = it
                        AppStore.setUseLocal(this, it)
                    },
                    onBack = { finish() },
                    onOpenRepos = { startActivity(Intent(this, RepositoryListActivity::class.java)) },
                    onOpenCloud = { startActivity(Intent(this, CloudModelsActivity::class.java)) },
                    onOpenTools = { startActivity(Intent(this, AgenticToolsActivity::class.java)) },
                    onOpenBrowser = { startActivity(Intent(this, ModelBrowserActivity::class.java)) },
                    onOpenDebugger = { startActivity(Intent(this, DebuggerActivity::class.java)) },
                    onOpenVhd = { startActivity(Intent(this, VhdListActivity::class.java)) },
                    onImportLocal = {
                        if (imported.isEmpty()) importLlm.launch(arrayOf("*/*"))
                        else showImport = true
                    },
                    enableDlss = enableDlss,
                    onEnableDlssChange = {
                        enableDlss = it
                        AppStore.setEnableDlss(this, it)
                        GuestRuntime.setUpscalerEnabled(it)
                    },
                    onImportUpscaler = { importUpscaler.launch(null) },
                    upscalerStatus = upscalerStatus.ifEmpty { modelStatus }
                )
                if (showImport) {
                    AlertDialog(
                        onDismissRequest = { showImport = false },
                        title = { Text("Imported models") },
                        text = {
                            Column {
                                imported.forEach { Text(it.substringAfterLast('/'), color = Color.White) }
                            }
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                showImport = false
                                importLlm.launch(arrayOf("*/*"))
                            }) { Text("Import from storage") }
                        },
                        dismissButton = { TextButton(onClick = { showImport = false }) { Text("Close") } }
                    )
                }
            }
        }
    }
}

@Composable
fun SettingsScreen(
    useLocal: Boolean,
    onUseLocalChange: (Boolean) -> Unit,
    onBack: () -> Unit,
    onOpenRepos: () -> Unit,
    onOpenCloud: () -> Unit,
    onOpenTools: () -> Unit,
    onOpenBrowser: () -> Unit,
    onOpenDebugger: () -> Unit,
    onOpenVhd: () -> Unit,
    onImportLocal: () -> Unit,
    enableDlss: Boolean,
    onEnableDlssChange: (Boolean) -> Unit,
    onImportUpscaler: () -> Unit,
    upscalerStatus: String
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0A0A12))
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.ArrowBack, "Back", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() })
            Spacer(Modifier.width(12.dp))
            Text("SETTINGS", color = Color(0xFF00E5FF), fontSize = 22.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(24.dp))

        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Use local AI", color = Color.White, modifier = Modifier.weight(1f))
            Switch(checked = useLocal, onCheckedChange = onUseLocalChange,
                colors = SwitchDefaults.colors(checkedTrackColor = Color(0xFF00E5FF)))
        }
        Spacer(Modifier.height(16.dp))

        SettingsButton("REPOSITORIES", true, onOpenRepos)
        Spacer(Modifier.height(10.dp))
        SettingsButton("CLOUD MODELS", enabled = !useLocal, onClick = onOpenCloud)
        Spacer(Modifier.height(10.dp))
        SettingsButton("AGENTIC TOOLS", true, onOpenTools)
        Spacer(Modifier.height(10.dp))
        SettingsButton("BROWSE MODELS", enabled = useLocal, onClick = onOpenBrowser)
        Spacer(Modifier.height(10.dp))
        SettingsButton("IMPORT LOCAL LLM (.gguf / .tflite / …)", enabled = useLocal, onClick = onImportLocal)
        Spacer(Modifier.height(10.dp))
        SettingsButton("DEBUGGER", true, onOpenDebugger)
        Spacer(Modifier.height(10.dp))
        SettingsButton("VIRTUAL HARD DISKS", true, onOpenVhd)

        Spacer(Modifier.height(24.dp))
        Text("PERFORMANCE", color = Color(0xFF7C4DFF), fontSize = 16.sp,
            fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(12.dp))
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text("DLSS-style upscaling for games", color = Color.White)
                Text(
                    "Applies image upscaling to programs detected as games",
                    color = Color.White.copy(alpha = 0.55f), fontSize = 11.sp
                )
            }
            Switch(checked = enableDlss, onCheckedChange = onEnableDlssChange,
                colors = SwitchDefaults.colors(checkedTrackColor = Color(0xFF00E5FF)))
        }
        Spacer(Modifier.height(10.dp))
        // Greyed out + disabled while DLSS is off; enabled when on.
        SettingsButton(
            "IMPORT IMAGE UPSCALER MODEL (folder)",
            enabled = enableDlss,
            onClick = onImportUpscaler
        )
        Spacer(Modifier.height(6.dp))
        Text(
            if (upscalerStatus != "{}") "upscaler: $upscalerStatus"
            else if (enableDlss) "no upscaler model imported yet"
            else "enable DLSS-style upscaling to import a model",
            color = Color.White.copy(alpha = 0.6f), fontSize = 11.sp
        )
    }
}

@Composable
private fun SettingsButton(label: String, enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(52.dp),
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color(0xFF00E5FF),
            contentColor = Color.Black,
            disabledContainerColor = Color(0xFF00E5FF).copy(alpha = 0.25f),
            disabledContentColor = Color.Black.copy(alpha = 0.4f)
        )
    ) { Text(label, fontWeight = FontWeight.Bold) }
}
