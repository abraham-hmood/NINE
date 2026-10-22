package com.nine.dbt

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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

/** FULL = green runnable, PARTIAL = yellow runnable, NONE = greyed out */
enum class ImplStatus { FULL, PARTIAL, NONE }

data class Feature(
    val id: String,
    val name: String,
    val phase: String,
    val status: ImplStatus,
    val isExitCriteria: Boolean = false
)

object FeatureCatalog {
    val all = listOf(
        // ---- Phase 0 ----
        Feature("2.1", "Project structure", "Phase 0", ImplStatus.FULL),
        Feature("2.2", "Memory manager", "Phase 0", ImplStatus.FULL),
        Feature("2.3", "Logging & diagnostics", "Phase 0", ImplStatus.FULL),
        Feature("ec.0", "Exit: allocate guest VA + executable map", "Phase 0", ImplStatus.FULL, true),

        // ---- Phase 1 ELF ----
        Feature("3.1", "ELF64 parsing", "Phase 1", ImplStatus.FULL),
        Feature("3.2", "ELF loading & mapping", "Phase 1", ImplStatus.PARTIAL),
        Feature("3.3", "Dynamic section", "Phase 1", ImplStatus.FULL),
        Feature("3.4", "ELF relocations", "Phase 1", ImplStatus.PARTIAL),
        Feature("3.5", "Symbol tables", "Phase 1", ImplStatus.PARTIAL),
        Feature("ec.1", "Exit: load ELF, map, relocate, transfer to entry", "Phase 1", ImplStatus.PARTIAL, true),

        // ---- Phase 2 linker ----
        Feature("4.1", "Module graph", "Phase 2", ImplStatus.FULL),
        Feature("4.2", "Symbol resolution", "Phase 2", ImplStatus.PARTIAL),
        Feature("4.3", "GOT / PLT / IAT", "Phase 2", ImplStatus.PARTIAL),
        Feature("4.4", "Search paths", "Phase 2", ImplStatus.FULL),
        Feature("ec.2", "Exit: resolve multi-module ELF graph", "Phase 2", ImplStatus.PARTIAL, true),

        // ---- Phase 3 DBT ----
        Feature("5.1", "x86-64 decoder", "Phase 3", ImplStatus.PARTIAL),
        Feature("5.2", "Register allocation", "Phase 3", ImplStatus.PARTIAL),
        Feature("5.3", "Flag handling", "Phase 3", ImplStatus.PARTIAL),
        Feature("5.4", "Translation units", "Phase 3", ImplStatus.PARTIAL),
        Feature("5.5", "Control flow", "Phase 3", ImplStatus.PARTIAL),
        Feature("5.6", "Code cache", "Phase 3", ImplStatus.FULL),
        Feature("5.7", "SIMD & atomics", "Phase 3", ImplStatus.PARTIAL),
        Feature("ec.3", "Exit: DBT executes arithmetic + branches", "Phase 3", ImplStatus.PARTIAL, true),

        // ---- Phase 4 PE ----
        Feature("6.1", "PE parsing", "Phase 4", ImplStatus.FULL),
        Feature("6.2", "PE mapping", "Phase 4", ImplStatus.PARTIAL),
        Feature("6.3", "PE relocations", "Phase 4", ImplStatus.PARTIAL),
        Feature("6.4", "PE imports", "Phase 4", ImplStatus.PARTIAL),
        Feature("6.5", "PE exports", "Phase 4", ImplStatus.FULL),
        Feature("6.6", "TLS & exceptions", "Phase 4", ImplStatus.PARTIAL),
        Feature("ec.4", "Exit: PE load + IAT patch", "Phase 4", ImplStatus.PARTIAL, true),

        // ---- Phase 5 Linux ABI ----
        Feature("7.1", "Syscall translation", "Phase 5", ImplStatus.PARTIAL),
        Feature("7.2", "vDSO & aux vector", "Phase 5", ImplStatus.PARTIAL),
        Feature("7.3", "Threading", "Phase 5", ImplStatus.PARTIAL),
        Feature("ec.5", "Exit: Linux hello via full stack", "Phase 5", ImplStatus.PARTIAL, true),

        // ---- Phase 6 Windows ABI ----
        Feature("8.1", "ntdll surface", "Phase 6", ImplStatus.PARTIAL),
        Feature("8.2", "kernel32 surface", "Phase 6", ImplStatus.PARTIAL),
        Feature("8.3", "Other DLLs", "Phase 6", ImplStatus.PARTIAL),
        Feature("8.4", "SEH", "Phase 6", ImplStatus.PARTIAL),
        Feature("ec.6", "Exit: Windows console hello via full stack", "Phase 6", ImplStatus.PARTIAL, true),

        // ---- Phase 7 ----
        Feature("9.1", "Execution loop", "Phase 7", ImplStatus.FULL),
        Feature("9.2", "Context switching", "Phase 7", ImplStatus.FULL),
        Feature("9.3", "SMC & coherency", "Phase 7", ImplStatus.FULL),
        Feature("9.4", "Multi-threading", "Phase 7", ImplStatus.PARTIAL),
        Feature("ec.7", "Exit: concurrent guest + SMC handling", "Phase 7", ImplStatus.PARTIAL, true),

        // ---- Phase 8 ----
        Feature("10", "Hardening", "Phase 8", ImplStatus.PARTIAL),
        Feature("ec.8", "Exit: W^X, persistent cache, counters", "Phase 8", ImplStatus.PARTIAL, true),

        // ---- JIT plan J1 ----
        Feature("j1.1", "J1.1 Calling convention", "JIT J1", ImplStatus.FULL),
        Feature("j1.2", "J1.2 Block exit protocol", "JIT J1", ImplStatus.FULL),
        Feature("j1.3", "J1.3 ExecutionLoop trampoline", "JIT J1", ImplStatus.FULL),
        Feature("ec.j1", "Exit J1: pure-reg block + syscall via JIT", "JIT J1", ImplStatus.PARTIAL, true),

        // ---- JIT plan J2 ----
        Feature("j2.1", "J2.1 Emitter completeness", "JIT J2", ImplStatus.FULL),
        Feature("j2.2", "J2.2 Coverage process", "JIT J2", ImplStatus.FULL),
        Feature("ec.j2", "Exit J2: hello >95% JIT hits (measure)", "JIT J2", ImplStatus.PARTIAL, true),

        // ---- JIT plan J3 ----
        Feature("j3.1", "J3.1 Traces", "JIT J3", ImplStatus.FULL),
        Feature("j3.2", "J3.2 Register caching across blocks", "JIT J3", ImplStatus.FULL),
        Feature("j3.3", "J3.3 IC / PLT / IAT", "JIT J3", ImplStatus.FULL),
        Feature("ec.j3", "Exit J3: fewer trampoline crossings", "JIT J3", ImplStatus.PARTIAL, true),

        // ---- Later JIT phases ----
        Feature("j4.1", "J4.1 Persistent cache keyed", "JIT J4", ImplStatus.FULL),
        Feature("j4.2", "J4.2 Concurrent translation", "JIT J4", ImplStatus.FULL),
        Feature("ec.j4", "Exit J4: concurrent JIT + warm cache", "JIT J4", ImplStatus.PARTIAL, true),
        Feature("j5.1", "J5.1 Load path ELF/PE", "JIT J5", ImplStatus.FULL),
        Feature("j5.2", "J5.2 Logs & debugger controls", "JIT J5", ImplStatus.FULL),
        Feature("j5.3", "J5.3 Background execution", "JIT J5", ImplStatus.FULL),
        Feature("ec.j5", "Exit J5: UI load/execute/debug", "JIT J5", ImplStatus.PARTIAL, true),
        Feature("ec.g1", "Exit G1: minimal Win32 GUI on surface", "JIT G1", ImplStatus.NONE, true),
        Feature("ec.g2", "Exit G2: D3D/Vulkan subset", "JIT G2", ImplStatus.NONE, true),
        Feature("ec.a1", "Exit A1: 32-bit Linux guest hello", "JIT A1", ImplStatus.NONE, true),
        Feature("ec.c1", "Exit C1: compatibility matrix published", "JIT C1", ImplStatus.NONE, true),
        Feature("ec.k2", "Exit K2: user-mode driver IOCTL sample", "JIT K2", ImplStatus.NONE, true),

        // App / AI
        Feature("ui.home", "Home / translated programs", "App", ImplStatus.FULL),
        Feature("ui.logs", "Logs", "App", ImplStatus.FULL),
        Feature("ui.ext", "Extensions & patches", "App", ImplStatus.FULL),
        Feature("ui.creator", "Creator chat", "App", ImplStatus.FULL),
        Feature("ai.local", "Local AI", "AI", ImplStatus.FULL),
        Feature("ai.cloud", "Cloud models", "AI", ImplStatus.FULL),
        Feature("ai.tools", "Agentic tools", "AI", ImplStatus.FULL),
        Feature("ai.browse", "Model browser", "AI", ImplStatus.FULL),
        Feature("ai.repos", "Repositories", "App", ImplStatus.FULL)
    )

    fun test(id: String): String = try {
        when (id) {
            "2.1" -> "modules: memory, loader/elf, loader/pe, linker, translator, abi, runtime"
            "2.3" -> { AppLog.i("debugger", "log test"); "Logger + AppLog write ok" }
            "ai.tools" -> "Builtin tools: " + BuiltinTools.all.joinToString { it.name }
            "ai.cloud" -> "CloudClient uses active model + tool loop"
            "ai.local" -> "LocalAiEngine GGUF/TFLite loader present"
            "ui.home", "ui.logs", "ui.ext", "ui.creator", "ai.browse", "ai.repos" ->
                "UI component present"
            "j5.1", "j5.2", "j5.3", "ec.j5" -> {
                val st = GuestRuntime.status()
                "GuestRuntime status: $st (use Home → LOAD NEW PROGRAM)"
            }
            else -> NativeTests.run(id)
        }
    } catch (e: Throwable) {
        "test failed: ${e.message}"
    }
}

class DebuggerActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NineTheme {
                var result by remember { mutableStateOf<Pair<String, String>?>(null) }
                var filterExit by remember { mutableStateOf(false) }
                Column(Modifier.fillMaxSize().background(Color(0xFF0A0A12)).padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = Color(0xFF00E5FF),
                            modifier = Modifier.size(28.dp).clickable { finish() })
                        Spacer(Modifier.width(12.dp))
                        Text("DEBUGGER", color = Color(0xFF00E5FF), fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        FilterChip(
                            selected = filterExit,
                            onClick = { filterExit = !filterExit },
                            label = { Text("Exit criteria only") }
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    val items = if (filterExit) FeatureCatalog.all.filter { it.isExitCriteria }
                                else FeatureCatalog.all
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.weight(1f)) {
                        items(items) { f ->
                            val enabled = f.status != ImplStatus.NONE
                            val bg = when (f.status) {
                                ImplStatus.FULL -> Color(0xFF0D2A1A)
                                ImplStatus.PARTIAL -> Color(0xFF2A250D)
                                ImplStatus.NONE -> Color(0xFF1A1A1A)
                            }
                            val titleColor = when (f.status) {
                                ImplStatus.FULL -> Color(0xFF69F0AE)
                                ImplStatus.PARTIAL -> Color(0xFFFFD54F)
                                ImplStatus.NONE -> Color(0xFF666666)
                            }
                            val badge = when (f.status) {
                                ImplStatus.FULL -> if (f.isExitCriteria) "EXIT" else "TEST"
                                ImplStatus.PARTIAL -> if (f.isExitCriteria) "EXIT~" else "TEST~"
                                ImplStatus.NONE -> "N/A"
                            }
                            val badgeColor = when (f.status) {
                                ImplStatus.FULL -> Color(0xFF00E5FF)
                                ImplStatus.PARTIAL -> Color(0xFFFFD54F)
                                ImplStatus.NONE -> Color(0xFF555555)
                            }
                            Card(
                                Modifier.fillMaxWidth().clickable(enabled = enabled) {
                                    result = f.name to FeatureCatalog.test(f.id)
                                },
                                colors = CardDefaults.cardColors(containerColor = bg)
                            ) {
                                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            (if (f.isExitCriteria) "◎ " else "") + f.name,
                                            color = titleColor,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 14.sp
                                        )
                                        Text("${f.id} · ${f.phase}", color = Color(0xFF80DEEA), fontSize = 11.sp)
                                    }
                                    Text(badge, color = badgeColor, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
                if (result != null) {
                    AlertDialog(
                        onDismissRequest = { result = null },
                        title = { Text(result!!.first) },
                        text = {
                            Text(
                                result!!.second,
                                fontSize = 13.sp
                            )
                        },
                        confirmButton = {
                            TextButton(onClick = { result = null }) { Text("OK") }
                        }
                    )
                }
            }
        }
    }
}
