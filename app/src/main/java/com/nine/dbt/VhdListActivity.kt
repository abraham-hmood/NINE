package com.nine.dbt

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class VhdListActivity : ComponentActivity() {

    private val vhds = mutableStateListOf<VhdManager.Vhd>()
    private val scope by lazy { kotlinx.coroutines.MainScope() }

    private val exportLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/gzip")) { uri ->
            if (uri == null) return@registerForActivityResult
            val ids = vhds.filter { it.id in selectedIds }.map { it.id }
            if (ids.isEmpty()) return@registerForActivityResult
            scope.launch(Dispatchers.IO) {
                val ok = runCatching {
                    contentResolver.openOutputStream(uri, "wt")?.use { out ->
                        VhdManager.exportTarGz(this@VhdListActivity, ids, out)
                    } ?: throw IllegalStateException("cannot open ${uri.lastPathSegment}")
                }
                runOnUiThread {
                    if (ok.isSuccess) {
                        GuestLog.info("vhd: exported ${ids.size} disk(s) to ${uri.lastPathSegment}")
                        snackbar("Exported ${ids.size} disk(s) as .tar.gz")
                    } else {
                        GuestLog.add("vhd: export failed: ${ok.exceptionOrNull()?.message}")
                        snackbar("Export failed: ${ok.exceptionOrNull()?.message}")
                    }
                    selectedIds = emptySet()
                }
            }
        }

    private var selectedIds by mutableStateOf(setOf<String>())
    private var pendingDelete by mutableStateOf(false)
    private var infoVhd by mutableStateOf<VhdManager.Vhd?>(null)
    private var snackbarMsg by mutableStateOf<String?>(null)

    private fun snackbar(msg: String) { snackbarMsg = msg }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NineTheme {
                val snackbarHostState = remember { SnackbarHostState() }
                LaunchedEffect(snackbarMsg) {
                    snackbarMsg?.let {
                        snackbarHostState.showSnackbar(it, duration = SnackbarDuration.Short)
                        snackbarMsg = null
                    }
                }
                Scaffold(
                    containerColor = Color(0xFF0A0A12),
                    snackbarHost = { SnackbarHost(snackbarHostState) },
                    floatingActionButton = {
                        FloatingActionButton(
                            onClick = { startActivity(Intent(this, VhdCreateActivity::class.java)) },
                            containerColor = Color(0xFF00E5FF),
                            contentColor = Color.Black
                        ) { Icon(Icons.Default.Add, "New VHD") }
                    }
                ) { pad ->
                    VhdListScreen(
                        vhds = vhds,
                        selectedIds = selectedIds,
                        onBack = { finish() },
                        onLongPress = { v ->
                            selectedIds =
                                if (v.id in selectedIds) selectedIds - v.id else selectedIds + v.id
                        },
                        onTap = { v ->
                            infoVhd = v
                            // last-viewed/tapped disk becomes the active VHD
                            // (used by all programs and shared with light shells)
                            VhdManager.setActive(this@VhdListActivity, v.id)
                        },
                        onClearSelection = { selectedIds = emptySet() },
                        onDelete = { pendingDelete = true },
                        onExport = {
                            val names = vhds.filter { it.id in selectedIds }
                            val name = when {
                                names.isEmpty() -> "nine-vhds.tar.gz"
                                names.size == 1 ->
                                    names[0].name.replace(Regex("[^A-Za-z0-9._-]"), "_") + ".tar.gz"
                                else -> "nine-vhds.tar.gz"
                            }
                            exportLauncher.launch(name)
                        },
                        modifier = Modifier.padding(pad)
                    )
                }

                if (pendingDelete) {
                    AlertDialog(
                        onDismissRequest = { pendingDelete = false },
                        title = { Text("Delete ${selectedIds.size} disk(s)?", color = Color.White) },
                        text = {
                            Text(
                                "This permanently deletes the selected virtual disks from app storage. " +
                                    "This cannot be undone.",
                                color = Color.White.copy(alpha = 0.7f)
                            )
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                val ids = selectedIds.toList()
                                runCatching { VhdManager.delete(this, ids) }
                                    .onSuccess {
                                        GuestLog.info("vhd: deleted ${ids.size} disk(s)")
                                        snackbar("Deleted ${ids.size} disk(s)")
                                    }
                                    .onFailure {
                                        GuestLog.add("vhd: delete failed: ${it.message}")
                                        snackbar("Delete failed: ${it.message}")
                                    }
                                vhds.clear(); vhds.addAll(VhdManager.list(this))
                    selectedIds = emptySet()
                                pendingDelete = false
                            }) { Text("Delete", color = Color(0xFFFF5252), fontWeight = FontWeight.Bold) }
                        },
                        dismissButton = {
                            TextButton(onClick = { pendingDelete = false }) { Text("Cancel", color = Color.White) }
                        }
                    )
                }

                infoVhd?.let { v ->
                    AlertDialog(
                        onDismissRequest = { infoVhd = null },
                        title = { Text(v.name, color = Color.White) },
                        text = {
                            Column {
                                InfoLine("Filesystem", v.fs)
                                InfoLine("Size", VhdManager.humanSize(v.sizeBytes))
                                InfoLine("Type", if (v.fixed) "Fixed (fully allocated)" else "Dynamic (growable)")
                                InfoLine("Stored", if (v.compressed) "Compressed (.vhd.gz)" else "Decompressed (.vhd)")
                                if (v.label.isNotBlank()) InfoLine("Label", v.label)
                                InfoLine("Sector size", "${v.sectorSize} B")
                                if (v.clusterBytes > 0) InfoLine("Cluster size", "${v.clusterBytes} B")
                                if (v.bootable) InfoLine("Bootable", "yes")
                                if (v.note.isNotBlank()) InfoLine("Note", v.note)
                                InfoLine("Created", SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                                    .format(Date(v.createdAt)))
                                InfoLine("Location", "files/vhds/${v.id}" +
                                    if (v.compressed) ".vhd.gz" else ".vhd")
                            }
                        },
                        confirmButton = {
                            TextButton(onClick = { infoVhd = null }) { Text("Close", color = Color(0xFF00E5FF)) }
                        }
                    )
                }
            }
        }
    }

    @Composable
    private fun InfoLine(k: String, v: String) {
        Row(Modifier.padding(bottom = 4.dp)) {
            Text("$k: ", color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp)
            Text(v, color = Color.White, fontSize = 12.sp)
        }
    }

    override fun onResume() {
        super.onResume()
        vhds.clear()
        vhds.addAll(VhdManager.list(this))
        // Drop selections for disks that disappeared
        selectedIds = selectedIds.intersect(vhds.map { it.id }.toSet())
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun VhdListScreen(
    vhds: List<VhdManager.Vhd>,
    selectedIds: Set<String>,
    onBack: () -> Unit,
    onLongPress: (VhdManager.Vhd) -> Unit,
    onTap: (VhdManager.Vhd) -> Unit,
    onClearSelection: () -> Unit,
    onDelete: () -> Unit,
    onExport: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFF0A0A12))
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Default.ArrowBack, "Back",
                tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() }
            )
            Spacer(Modifier.width(12.dp))
            Text(
                "VIRTUAL HARD DISKS", color = Color(0xFF00E5FF),
                fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Tap for details, long-press to select.",
            color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp
        )
        Spacer(Modifier.height(12.dp))

        if (vhds.isEmpty()) {
            Text(
                "No virtual hard disks yet. Tap + to create one.",
                color = Color.White.copy(alpha = 0.6f)
            )
            Spacer(Modifier.height(12.dp))
            Text(
                "VHDs are created in NINE's private app storage (files/vhds) only.",
                color = Color.White.copy(alpha = 0.4f), fontSize = 11.sp
            )
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(vhds, key = { it.id }) { v ->
                    val selected = v.id in selectedIds
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .then(
                                if (selected) Modifier.border(
                                    2.dp, Color(0xFF00E5FF), RoundedCornerShape(12.dp)
                                ) else Modifier
                            )
                            .combinedClickable(
                                onClick = { onTap(v) },
                                onLongClick = { onLongPress(v) }
                            ),
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (selected) Color(0xFF0F2A33) else Color(0xFF12121C)
                        )
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    v.name, color = Color.White,
                                    fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)
                                )
                                if (selected) {
                                    Text("SELECTED", color = Color(0xFF00E5FF), fontSize = 10.sp)
                                }
                            }
                            Text(
                                "${v.fs}  •  ${VhdManager.humanSize(v.sizeBytes)}  •  " +
                                    (if (v.fixed) "fixed" else "dynamic") +
                                    (if (v.compressed) "  •  compressed" else "  •  decompressed"),
                                color = Color(0xFF80DEEA), fontSize = 12.sp
                            )
                            if (v.label.isNotBlank())
                                Text(
                                    "label: ${v.label}", color = Color.White.copy(alpha = 0.5f),
                                    fontSize = 11.sp
                                )
                            if (v.note.isNotBlank())
                                Text(v.note, color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp)
                        }
                    }
                }
            }
        }

        if (selectedIds.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "${selectedIds.size} selected",
                    color = Color(0xFF00E5FF), fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = onClearSelection) {
                    Text("Clear", color = Color.White.copy(alpha = 0.7f), fontSize = 12.sp)
                }
                Spacer(Modifier.weight(1f))
                FloatingActionButton(
                    onClick = onDelete,
                    containerColor = Color(0xFF2A1215),
                    contentColor = Color(0xFFFF5252),
                    modifier = Modifier.size(44.dp)
                ) { Icon(Icons.Default.Delete, "Delete selected") }
                Spacer(Modifier.width(10.dp))
                FloatingActionButton(
                    onClick = onExport,
                    containerColor = Color(0xFF0F2A33),
                    contentColor = Color(0xFF00E5FF),
                    modifier = Modifier.size(44.dp)
                ) { Icon(Icons.Default.Share, "Export selected") }
            }
        }
    }
}
