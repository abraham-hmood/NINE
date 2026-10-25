package com.nine.dbt

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.text.KeyboardOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class VhdCreateActivity : ComponentActivity() {

    private val scope by lazy { kotlinx.coroutines.MainScope() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NineTheme {
                val snackbarHostState = remember { SnackbarHostState() }
                var snackbarMsg by remember { mutableStateOf<String?>(null) }
                LaunchedEffect(snackbarMsg) {
                    snackbarMsg?.let {
                        snackbarHostState.showSnackbar(it, duration = SnackbarDuration.Short)
                        snackbarMsg = null
                    }
                }

                var name by remember { mutableStateOf("") }
                var sizeText by remember { mutableStateOf("256") }
                var unit by remember { mutableStateOf("MB") }
                var fs by remember { mutableStateOf("FAT32") }
                var fixedSize by remember { mutableStateOf(true) }
                var compress by remember { mutableStateOf(false) }
                var more by remember { mutableStateOf(false) }
                var label by remember { mutableStateOf("") }
                var sectorSize by remember { mutableStateOf("512") }
                var clusterBytes by remember { mutableStateOf("auto") }
                var bootable by remember { mutableStateOf(false) }
                var note by remember { mutableStateOf("") }
                var creating by remember { mutableStateOf(false) }
                var error by remember { mutableStateOf<String?>(null) }

                val unitFactor = when (unit) {
                    "KB" -> 1024L
                    "GB" -> 1024L * 1024 * 1024
                    "TB" -> 1024L * 1024 * 1024 * 1024
                    else -> 1024L * 1024 // MB
                }

                fun submit() {
                    val size = sizeText.trim().toLongOrNull()
                    val bytes = (size ?: 0L) * unitFactor
                    error = when {
                        name.isBlank() -> "Name is required"
                        size == null || size < 1 -> "Size must be a positive number"
                        bytes < 1024 * 1024 -> "Size must be at least 1 MB"
                        fs !in VhdManager.FILESYSTEMS -> "Unsupported filesystem"
                        else -> null
                    }
                    if (error != null) return

                    val spec = VhdManager.CreateSpec(
                        name = name.trim(),
                        fs = fs,
                        sizeBytes = bytes,
                        fixed = fixedSize,
                        compressed = compress,
                        label = label.trim(),
                        sectorSize = sectorSize.toIntOrNull() ?: 512,
                        clusterBytes = if (clusterBytes == "auto") 0
                                       else clusterBytes.removeSuffix("B").toIntOrNull() ?: 0,
                        bootable = bootable,
                        note = note.trim()
                    )
                    creating = true
                    scope.launch(Dispatchers.IO) {
                        val res = runCatching { VhdManager.create(this@VhdCreateActivity, spec) }
                        runOnUiThread {
                            creating = false
                            if (res.isSuccess) {
                                snackbarMsg = "VHD '${spec.name}' created (${VhdManager.humanSize(spec.sizeBytes)})"
                                scope.launch {
                                    delay(1200)
                                    finish()
                                }
                            } else {
                                val m = res.exceptionOrNull()?.message ?: "unknown error"
                                GuestLog.add("vhd: create failed: $m")
                                error = m
                            }
                        }
                    }
                }

                Scaffold(
                    containerColor = Color(0xFF0A0A12),
                    snackbarHost = { DismissibleSnackbarHost(snackbarHostState) },
                    floatingActionButton = {
                        FloatingActionButton(
                            onClick = { if (!creating) submit() },
                            containerColor = Color(0xFF00E5FF),
                            contentColor = Color.Black,
                            modifier = Modifier.size(56.dp)
                        ) {
                            if (creating) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(24.dp),
                                    color = Color.Black, strokeWidth = 2.dp
                                )
                            } else {
                                Icon(Icons.Default.Save, "Create VHD")
                            }
                        }
                    }
                ) { pad ->
                    Column(
                        modifier = Modifier
                            .padding(pad)
                            .fillMaxSize()
                            .background(Color(0xFF0A0A12))
                            .verticalScroll(rememberScrollState())
                            .padding(16.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Default.ArrowBack, "Back",
                                tint = Color(0xFF00E5FF),
                                modifier = Modifier.size(28.dp).clickable { finish() }
                            )
                            Spacer(Modifier.width(12.dp))
                            Text(
                                "NEW VIRTUAL DISK", color = Color(0xFF00E5FF),
                                fontSize = 22.sp, fontWeight = FontWeight.Bold
                            )
                        }
                        Spacer(Modifier.height(16.dp))
                        Text(
                            "Created in NINE app storage only (files/vhds). " +
                                "Fixed disks are allocated fully; dynamic disks grow on write.",
                            color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp
                        )
                        Spacer(Modifier.height(16.dp))

                        NineTextField("Name", name, { name = it }, "e.g. win95-data")
                        Spacer(Modifier.height(12.dp))

                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            NineTextField(
                                "Size", sizeText, { sizeText = it },
                                "256", keyboardType = KeyboardType.Number,
                                modifier = Modifier.weight(1.4f)
                            )
                            NineDropdown(
                                "Unit", unit, listOf("KB", "MB", "GB", "TB"),
                                modifier = Modifier.weight(1f)
                            ) { unit = it }
                        }
                        Spacer(Modifier.height(12.dp))

                        NineDropdown(
                            "Filesystem", fs, VhdManager.FILESYSTEMS
                        ) { fs = it }
                        Spacer(Modifier.height(16.dp))

                        SettingsCheckbox(
                            "Fixed size",
                            "Fully allocate ${sizeText.ifBlank { "?" }} $unit now (safer, uses space immediately)",
                            fixedSize
                        ) { fixedSize = it }
                        SettingsCheckbox(
                            "Compress when not in use",
                            "Store as .vhd.gz; decompressed while NINE runs, recompressed on leave (saves storage)",
                            compress
                        ) { compress = it }

                        Spacer(Modifier.height(8.dp))
                        Text(
                            if (more) "▾ MORE OPTIONS" else "▸ MORE OPTIONS",
                            color = Color(0xFF00E5FF), fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { more = !more }
                                .padding(vertical = 6.dp)
                        )

                        if (more) {
                            Spacer(Modifier.height(8.dp))
                            NineTextField("Volume label", label, { label = it }, "optional (11 chars)")
                            Spacer(Modifier.height(12.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                NineDropdown(
                                    "Sector size", sectorSize,
                                    listOf("512", "1024", "2048", "4096"),
                                    modifier = Modifier.weight(1f)
                                ) { sectorSize = it }
                                NineDropdown(
                                    "Cluster size", clusterBytes,
                                    listOf("auto", "512B", "1KB", "2KB", "4KB", "8KB", "16KB", "32KB", "64KB"),
                                    modifier = Modifier.weight(1f)
                                ) { clusterBytes = it }
                            }
                            Spacer(Modifier.height(12.dp))
                            SettingsCheckbox(
                                "Bootable", "Mark partition bootable in the MBR", bootable
                            ) { bootable = it }
                            Spacer(Modifier.height(12.dp))
                            NineTextField("Note", note, { note = it }, "stored with the disk metadata")
                        }

                        error?.let {
                            Spacer(Modifier.height(12.dp))
                            Text(it, color = Color(0xFFFF5252), fontSize = 13.sp)
                        }

                        Spacer(Modifier.height(96.dp)) // room for FAB
                        if (creating) {
                            LinearProgressIndicator(
                                modifier = Modifier.fillMaxWidth(),
                                color = Color(0xFF00E5FF)
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                "Formatting ${fs} — this can take a while for large fixed disks…",
                                color = Color.White.copy(alpha = 0.6f), fontSize = 11.sp
                            )
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}

@Composable
private fun NineTextField(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    placeholder: String = "",
    keyboardType: KeyboardType = KeyboardType.Text,
    modifier: Modifier = Modifier
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label, color = Color(0xFF00E5FF)) },
        placeholder = { Text(placeholder, color = Color.White.copy(alpha = 0.35f)) },
        modifier = modifier.fillMaxWidth(),
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Color(0xFF00E5FF),
            unfocusedBorderColor = Color(0xFF33334D),
            focusedTextColor = Color.White,
            unfocusedTextColor = Color.White,
            cursorColor = Color(0xFF00E5FF),
            focusedLabelColor = Color(0xFF00E5FF),
            unfocusedLabelColor = Color.White.copy(alpha = 0.5f)
        )
    )
}

@Composable
private fun NineDropdown(
    label: String,
    value: String,
    options: List<String>,
    modifier: Modifier = Modifier,
    onPick: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    Box(modifier = modifier) {
        Surface(
            shape = RoundedCornerShape(6.dp),
            color = Color(0xFF12121C),
            border = androidx.compose.foundation.BorderStroke(
                1.dp, if (expanded) Color(0xFF00E5FF) else Color(0xFF33334D)
            ),
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = true }
        ) {
            Column(Modifier.padding(horizontal = 14.dp, vertical = 9.dp)) {
                Text(label, color = Color(0xFF00E5FF), fontSize = 11.sp)
                Text(value, color = Color.White, fontSize = 15.sp)
            }
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            modifier = Modifier
                .fillMaxWidth(0.9f)
                .background(Color(0xFF12121C))
        ) {
            options.forEach { opt ->
                DropdownMenuItem(
                    text = {
                        Text(
                            opt,
                            color = if (opt == value) Color(0xFF00E5FF) else Color.White,
                            fontWeight = if (opt == value) FontWeight.Bold else FontWeight.Normal
                        )
                    },
                    onClick = {
                        onPick(opt)
                        expanded = false
                    }
                )
            }
        }
    }
}

@Composable
private fun SettingsCheckbox(
    title: String,
    sub: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onChange(!checked) }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(
            checked = checked,
            onCheckedChange = onChange,
            colors = CheckboxDefaults.colors(checkedColor = Color(0xFF00E5FF))
        )
        Column(Modifier.weight(1f)) {
            Text(title, color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Text(sub, color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp)
        }
    }
}
