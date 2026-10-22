package com.nine.dbt

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
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

class SettingsActivity : ComponentActivity() {
    private val importLlm = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri?.let {
            try {
                contentResolver.takePersistableUriPermission(it, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            } catch (_: Exception) {}
            AppStore.setLocalModelUri(this, it.toString())
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NineTheme {
                var useLocal by remember { mutableStateOf(AppStore.useLocal(this)) }
                var showImport by remember { mutableStateOf(false) }
                val imported = AppStore.localModels(this)
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
                    }
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
    onImportLocal: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0A0A12))
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
