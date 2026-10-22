package com.nine.dbt

import android.app.ActivityManager
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Sort
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.URL

class ModelBrowserActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mem = ActivityManager.MemoryInfo()
        am.getMemoryInfo(mem)
        val ramMb = mem.totalMem / (1024 * 1024)
        val hasNpu = packageManager.hasSystemFeature("android.hardware.neuralnetworks") ||
            packageManager.hasSystemFeature("android.hardware.vulkan.compute")

        setContent {
            NineTheme {
                ModelBrowserScreen(ramMb, hasNpu, onBack = { finish() }) { model, quant ->
                    download(model, quant)
                }
            }
        }
    }

    private fun download(model: RemoteModel, quant: ModelQuant) {
        ModelDownloader.download(this, model, quant)
    }
}

@Composable
fun ModelBrowserScreen(
    ramMb: Long,
    hasNpu: Boolean,
    onBack: () -> Unit,
    onDownload: (RemoteModel, ModelQuant) -> Unit
) {
    var query by remember { mutableStateOf("") }
    var models by remember { mutableStateOf<List<RemoteModel>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var sort by remember { mutableStateOf("name") }
    var filterCpu by remember { mutableStateOf(true) }
    var filterNpu by remember { mutableStateOf(hasNpu) }
    var filterRam by remember { mutableStateOf(true) }
    var filterGguf by remember { mutableStateOf(true) }
    var filterTflite by remember { mutableStateOf(true) }
    var filterSmall by remember { mutableStateOf(false) }
    var showSort by remember { mutableStateOf(false) }
    var showFilter by remember { mutableStateOf(false) }
    var pickModel by remember { mutableStateOf<RemoteModel?>(null) }
    var pickedQuant by remember { mutableStateOf<ModelQuant?>(null) }
    val scope = rememberCoroutineScope()

    fun refresh() {
        loading = true
        scope.launch {
            val raw = withContext(Dispatchers.IO) { ModelCatalog.search(query) }
            models = raw.filter { m ->
                (!filterCpu || m.runsOnCpu) &&
                (!filterNpu || !hasNpu || m.runsOnNpu || m.runsOnCpu) &&
                (!filterRam || m.minRamMb <= ramMb) &&
                (if (filterGguf && filterTflite) true
                 else if (filterGguf) m.type == "gguf"
                 else if (filterTflite) m.type == "tflite" || m.type == "task"
                 else true) &&
                (!filterSmall || m.sizeMb < 4000)
            }
            models = when (sort) {
                "storage" -> models.sortedBy { it.sizeMb }
                "author" -> models.sortedBy { it.author }
                "quants" -> models.sortedByDescending { it.quants.size }
                else -> models.sortedBy { it.name }
            }
            loading = false
        }
    }

    LaunchedEffect(Unit) { refresh() }

    Column(Modifier.fillMaxSize().background(Color(0xFF0A0A12)).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.ArrowBack, "Back", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() })
            Spacer(Modifier.width(12.dp))
            Text("MODELS", color = Color(0xFF00E5FF), fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Box {
                Icon(Icons.Default.Sort, "Sort", tint = Color(0xFF00E5FF),
                    modifier = Modifier.size(28.dp).clickable { showSort = true })
                DropdownMenu(expanded = showSort, onDismissRequest = { showSort = false }) {
                    listOf("name", "storage", "author", "quants").forEach { s ->
                        DropdownMenuItem(text = { Text("Sort by $s") }, onClick = { sort = s; showSort = false; refresh() })
                    }
                }
            }
            Spacer(Modifier.width(8.dp))
            Box {
                Icon(Icons.Default.FilterList, "Filter", tint = Color(0xFF00E5FF),
                    modifier = Modifier.size(28.dp).clickable { showFilter = true })
                DropdownMenu(expanded = showFilter, onDismissRequest = { showFilter = false }) {
                    DropdownMenuItem(text = { Text("CPU ${if (filterCpu) "✓" else ""}") }, onClick = { filterCpu = !filterCpu; refresh() })
                    DropdownMenuItem(text = { Text("NPU ${if (filterNpu) "✓" else ""}") }, onClick = { filterNpu = !filterNpu; refresh() })
                    DropdownMenuItem(text = { Text("Fits RAM ${if (filterRam) "✓" else ""}") }, onClick = { filterRam = !filterRam; refresh() })
                    DropdownMenuItem(text = { Text("GGUF ${if (filterGguf) "✓" else ""}") }, onClick = { filterGguf = !filterGguf; refresh() })
                    DropdownMenuItem(text = { Text("TFLite/task ${if (filterTflite) "✓" else ""}") }, onClick = { filterTflite = !filterTflite; refresh() })
                    DropdownMenuItem(text = { Text("Under 4GB ${if (filterSmall) "✓" else ""}") }, onClick = { filterSmall = !filterSmall; refresh() })
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = query, onValueChange = { query = it },
            label = { Text("Search Hugging Face / GitHub") },
            trailingIcon = { Icon(Icons.Default.Search, "Search", modifier = Modifier.clickable { refresh() }) },
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFF00E5FF), unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
                focusedTextColor = Color.White, unfocusedTextColor = Color.White
            )
        )
        Spacer(Modifier.height(8.dp))
        Text("Device: ${ramMb}MB RAM · NPU ${if (hasNpu) "yes" else "no"}", color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp)
        Spacer(Modifier.height(8.dp))
        if (loading) CircularProgressIndicator(color = Color(0xFF00E5FF))
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(models) { m ->
                Card(
                    Modifier.fillMaxWidth().clickable {
                        if (m.quants.size <= 1) onDownload(m, m.quants.first())
                        else { pickModel = m; pickedQuant = m.quants.first() }
                    },
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF12121C))
                ) {
                    Column(Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(m.name, color = Color.White, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                            if (m.supportsTools) {
                                Text(
                                    "tools",
                                    color = Color.Black,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier
                                        .background(Color(0xFF69F0AE), RoundedCornerShape(50))
                                        .padding(horizontal = 8.dp, vertical = 2.dp)
                                )
                            }
                        }
                        Text("${m.author} · ${m.type} · ${m.quants.size} quant(s) · ${m.source}",
                            color = Color(0xFF80DEEA), fontSize = 12.sp)
                        val prog = ModelDownloader.progress[m.name]
                        if (prog != null && !prog.done) {
                            Spacer(Modifier.height(6.dp))
                            LinearProgressIndicator(
                                progress = { prog.percent / 100f },
                                modifier = Modifier.fillMaxWidth(),
                                color = Color(0xFF00E5FF)
                            )
                            Text("${prog.percent}%", color = Color.White.copy(alpha = 0.6f), fontSize = 11.sp)
                        } else if (prog != null && prog.done && prog.path != null) {
                            Text("Imported", color = Color(0xFF69F0AE), fontSize = 11.sp)
                        }
                    }
                }
            }
        }
    }

    if (pickModel != null) {
        AlertDialog(
            onDismissRequest = { pickModel = null },
            title = { Text(pickModel!!.name) },
            text = {
                Column {
                    pickModel!!.quants.forEach { q ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(selected = pickedQuant == q, onClick = { pickedQuant = q })
                            Text(q.label, color = Color.White)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    pickedQuant?.let { onDownload(pickModel!!, it) }
                    pickModel = null
                }) { Text("OK") }
            },
            dismissButton = { TextButton(onClick = { pickModel = null }) { Text("Cancel") } }
        )
    }
}
