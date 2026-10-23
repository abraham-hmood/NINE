package com.nine.dbt

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Bundle
import androidx.compose.ui.platform.LocalContext
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Create
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.LibraryBooks
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.*
import androidx.compose.runtime.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            NineTheme {
                NineApp()
            }
        }
    }
}

@Composable
fun NineTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFF00E5FF),
            secondary = Color(0xFF7C4DFF),
            background = Color(0xFF0A0A12),
            surface = Color(0xFF12121C),
            onPrimary = Color.Black,
            onBackground = Color.White,
            onSurface = Color.White
        ),
        content = content
    )
}

@Composable
fun NineApp() {
    var selectedTab by remember { mutableIntStateOf(0) }
    val context = LocalContext.current
    val activity = context as ComponentActivity
    val scope = rememberCoroutineScope()
    val programs = remember {
        mutableStateListOf<LibraryProgram>().apply { addAll(ProgramLibrary.all(context)) }
    }
    var showTutorial by remember { mutableStateOf(!AppStore.tutorialDone(context)) }

    val play: (LibraryProgram) -> Unit = { p ->
        scope.launch {
            val path = p.execPath(context).absolutePath
            GuestLog.info("launch ${p.name} ($path)")
            GuestRuntime.loadAndRunAsync(path, context.cacheDir)
        }
    }

    // Built-in Android document picker (SAF) for ELF / .o / .exe / .zip
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val res = withContext(Dispatchers.IO) {
                    runCatching { ProgramLibrary.importFromUri(context, uri) }
                }
                res.onSuccess { p ->
                    ProgramLibrary.add(context, p)
                    programs.add(0, p)
                    GuestLog.info(
                        "imported ${p.name} [${p.os}/${p.kind}] exec=${p.execRel} libDirs=${p.libDirs.size}"
                    )
                    selectedTab = 0
                }.onFailure {
                    GuestLog.add("import failed: ${it.message}")
                }
            }
        }
    }
    val loadClick: () -> Unit = { importLauncher.launch(arrayOf("*/*")) }

    // SAF "Save as" dialog for exporting selected programs as a zip
    var pendingExport by remember { mutableStateOf<List<LibraryProgram>>(emptyList()) }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        val targets = pendingExport
        pendingExport = emptyList()
        if (uri != null && targets.isNotEmpty()) {
            scope.launch {
                val res = withContext(Dispatchers.IO) {
                    runCatching { ProgramLibrary.exportPrograms(context, targets, uri) }
                }
                res.onSuccess { GuestLog.info("exported ${targets.size} program(s) to archive") }
                    .onFailure { GuestLog.add("export failed: ${it.message}") }
            }
        }
    }

    // Relink selected programs against NINE's ABI (native, structured JSON),
    // then package successes + NINE's compiled library + config.json
    // (libraries + VHD install paths) into a deployable zip.
    var pendingPackage by remember {
        mutableStateOf<List<Pair<LibraryProgram, RelinkResult>>>(emptyList())
    }
    val packageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        val entries = pendingPackage
        pendingPackage = emptyList()
        if (uri != null && entries.isNotEmpty()) {
            scope.launch {
                val res = withContext(Dispatchers.IO) {
                    runCatching { ProgramLibrary.exportPackaged(context, entries, uri) }
                }
                res.onSuccess {
                    GuestLog.info(
                        "packaged ${entries.size} program(s) + NINE ABI library + config.json"
                    )
                }.onFailure {
                    GuestLog.add("package failed: ${it.message}")
                }
            }
        }
    }

    val relink: (List<LibraryProgram>) -> Unit = { targets ->
        scope.launch {
            val linked = mutableListOf<Pair<LibraryProgram, RelinkResult>>()
            targets.forEach { p ->
                GuestLog.info("relink ${p.name}…")
                val r = withContext(Dispatchers.IO) {
                    GuestRuntime.relinkResult(
                        p.execPath(context).absolutePath, p.libDirPaths(context)
                    )
                }
                if (r.ok) {
                    GuestLog.info("relink ${p.name}: ${r.summary}")
                    r.libraries.forEach { l ->
                        GuestLog.info("  ${l.name} [${l.provider}] -> ${l.installPath}")
                    }
                    // force all relinked (and thus light-shelled) programs onto
                    // the user's active virtual hard disk
                    val vhdPath = VhdManager.activeImagePath(context)
                    if (vhdPath.isNotEmpty())
                        ProgramLibrary.setVhdPath(context, p, vhdPath)
                    val updated = p.copy(status = "Linked")
                    ProgramLibrary.update(context, updated)
                    ProgramLibrary.saveRelinkToConfig(context, updated, r)
                    val i = programs.indexOfFirst { it.id == p.id }
                    if (i >= 0) programs[i] = updated
                    linked += p to r

                    // relinked program → build + try to install a light shell
                    try {
                        withContext(Dispatchers.IO) {
                            LightShellPackager.buildAndInstall(context, updated)
                        }
                    } catch (e: Throwable) {
                        GuestLog.add("light shell build failed: ${e.message}")
                        GuestLog.add(
                            java.util.Arrays.toString(e.stackTrace.take(8).toTypedArray())
                        )
                    }
                } else {
                    GuestLog.add("relink ${p.name} FAILED: ${r.error}")
                    r.unresolved.forEach { GuestLog.add("  unresolved: $it") }
                }
            }
            if (linked.isNotEmpty()) {
                pendingPackage = linked
                packageLauncher.launch("nine-relinked.zip")
            }
        }
    }

    // VHD lifecycle messages (published by NineApplication) as snackbars
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(Unit) {
        snapshotFlow { VhdEvents.message }.collect { m ->
            if (!m.isNullOrBlank()) {
                snackbarHostState.showSnackbar(m, duration = SnackbarDuration.Long)
                VhdEvents.message = null
            }
        }
    }

    // One-off All-files-access prompt (light shells save to /sdcard/NINE/shells).
    // The tutorial path only runs on first launch, so this catches upgrades.
    val activityContext = LocalContext.current
    var showAllFilesAsk by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 30 && !Environment.isExternalStorageManager() &&
            !AppStore.allFilesPrompted(activityContext)
        ) {
            AppStore.setAllFilesPrompted(activityContext)
            showAllFilesAsk = true
        }
    }
    if (showAllFilesAsk) {
        AlertDialog(
            onDismissRequest = { showAllFilesAsk = false },
            title = { Text("All files access") },
            text = {
                Text(
                    "NINE saves light-shell APKs to /sdcard/NINE/shells and shares" +
                    " the active virtual hard disk with them. Grant All files access" +
                    " on the next screen (it is a system setting, not a dialog)."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showAllFilesAsk = false
                    try {
                        activityContext.startActivity(Intent(
                            android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                            Uri.parse("package:${activityContext.packageName}")
                        ))
                    } catch (_: Throwable) {
                        try {
                            activityContext.startActivity(Intent(
                                android.provider.Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION
                            ))
                        } catch (_: Throwable) {}
                    }
                }) { Text("Open settings") }
            },
            dismissButton = {
                TextButton(onClick = { showAllFilesAsk = false }) { Text("Later") }
            }
        )
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            NavigationBar(
                containerColor = Color(0xFF0D0D14),
                contentColor = Color(0xFF00E5FF)
            ) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Home, contentDescription = "Home") },
                    label = { Text("Home") }
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.LibraryBooks, contentDescription = "Library") },
                    label = { Text("Library") }
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.Default.Terminal, contentDescription = "Logs") },
                    label = { Text("Logs") }
                )
                NavigationBarItem(
                    selected = selectedTab == 3,
                    onClick = { selectedTab = 3 },
                    icon = { Icon(Icons.Default.Extension, contentDescription = "Extensions") },
                    label = { Text("Extensions") }
                )
                NavigationBarItem(
                    selected = selectedTab == 4,
                    onClick = { selectedTab = 4 },
                    icon = { Icon(Icons.Default.Create, contentDescription = "Creator") },
                    label = { Text("Creator") }
                )
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFF0A0A12))
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 24.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "9",
                        fontSize = 32.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF00E5FF),
                        letterSpacing = 2.sp
                    )
                    Text(
                        text = "NINE IS NOT AN EMULATOR",
                        fontSize = 11.sp,
                        color = Color(0xFF80DEEA),
                        letterSpacing = 1.sp
                    )
                }
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = "Settings",
                    tint = Color(0xFF00E5FF),
                    modifier = Modifier
                        .size(28.dp)
                        .clickable {
                            context.startActivity(Intent(context, SettingsActivity::class.java))
                        }
                )
            }

            if (selectedTab == 0) {
                RuntimeStatusCard()
                Spacer(Modifier.height(12.dp))
            }

            val sectionTitle = when (selectedTab) {
                0 -> "RECENTLY TRANSLATED PROGRAMS"
                1 -> "LIBRARY"
                2 -> "TRANSLATION LOGS"
                else -> null
            }
            if (sectionTitle != null) {
                Text(
                    text = sectionTitle,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color.White.copy(alpha = 0.7f),
                    modifier = Modifier.padding(top = 16.dp, bottom = 4.dp)
                )
                if (selectedTab != 2) {
                    Text(
                        text = "Active: x86-64 → ARMv9 NEON",
                        fontSize = 12.sp,
                        color = Color(0xFF00E5FF),
                        modifier = Modifier.padding(bottom = 12.dp)
                    )
                }
            }

            when (selectedTab) {
                0 -> HomeContent(programs, onLoadClick = loadClick, onPlay = play)
                1 -> LibraryContent(
                    programs = programs,
                    onPlay = play,
                    onRelink = relink,
                    onExport = { targets ->
                        pendingExport = targets
                        exportLauncher.launch("nine-library.zip")
                    }
                )
                2 -> LogsContent()
                3 -> ExtensionsContent()
                4 -> CreatorContent()
            }
            if (showTutorial) {
                TutorialOverlay(activity, onTab = { selectedTab = it }) {
                    AppStore.setTutorialDone(context)
                    showTutorial = false
                }
            }
        }
    }
}

/** Live runtime state: polls GuestRuntime every 250 ms + Pause/Resume/Stop. */
@Composable
fun RuntimeStatusCard() {
    var statusText by remember { mutableStateOf(GuestRuntime.lastStatus.ifBlank { "idle" }) }
    var running by remember { mutableStateOf(GuestRuntime.isRunning) }
    LaunchedEffect(Unit) {
        while (true) {
            running = GuestRuntime.isRunning
            statusText = GuestRuntime.status().ifBlank { "idle" }
            delay(250)
        }
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF12121C))
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "RUNTIME", color = Color(0xFF00E5FF),
                    fontSize = 13.sp, fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    if (running) "RUNNING" else "IDLE",
                    color = if (running) Color(0xFF69F0AE) else Color.White.copy(alpha = 0.5f),
                    fontSize = 11.sp, fontWeight = FontWeight.Bold
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                statusText,
                color = Color.White.copy(alpha = 0.85f),
                fontSize = 12.sp,
                maxLines = 3
            )
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { GuestLog.info("runtime: pause"); GuestRuntime.pause() },
                    enabled = running,
                    modifier = Modifier.weight(1f)
                ) { Text("Pause", fontSize = 12.sp) }
                OutlinedButton(
                    onClick = { GuestLog.info("runtime: resume"); GuestRuntime.resume() },
                    enabled = running,
                    modifier = Modifier.weight(1f)
                ) { Text("Resume", fontSize = 12.sp) }
                Button(
                    onClick = { GuestLog.info("runtime: stop"); GuestRuntime.stop() },
                    enabled = running,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFFFF5252),
                        disabledContainerColor = Color(0xFFFF5252).copy(alpha = 0.25f)
                    )
                ) { Text("Stop", fontSize = 12.sp) }
            }
        }
    }
}

@Composable
fun HomeContent(
    programs: List<LibraryProgram>,
    onLoadClick: () -> Unit,
    onPlay: (LibraryProgram) -> Unit
) {
    if (programs.isEmpty()) {
        // Empty state
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(vertical = 48.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "No translated programs yet",
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium,
                color = Color.White.copy(alpha = 0.8f)
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Translate a program for it to show up here.",
                fontSize = 14.sp,
                color = Color.White.copy(alpha = 0.5f),
                modifier = Modifier.padding(horizontal = 32.dp)
            )
            Spacer(modifier = Modifier.height(24.dp))
            Button(
                onClick = onLoadClick,
                modifier = Modifier
                    .fillMaxWidth(0.8f)
                    .height(52.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF00E5FF),
                    contentColor = Color.Black
                )
            ) {
                Text("LOAD NEW PROGRAM (+)", fontWeight = FontWeight.Bold)
            }
        }
    } else {
        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(bottom = 16.dp)
        ) {
            items(programs, key = { it.id }) { program ->
                ProgramCard(
                    program,
                    onPlay = { onPlay(program) },
                    onClick = { onPlay(program) }
                )
            }
            item {
                Button(
                    onClick = onLoadClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                        .height(52.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF00E5FF),
                        contentColor = Color.Black
                    )
                ) {
                    Text("LOAD NEW PROGRAM (+)", fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ProgramCard(
    program: LibraryProgram,
    selected: Boolean = false,
    onClick: (() -> Unit)? = null,
    onLongClick: (() -> Unit)? = null,
    onPlay: (() -> Unit)? = null
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(
                Brush.linearGradient(
                    colors = listOf(
                        Color(0xFF1A1A28),
                        Color(0xFF12121C)
                    )
                )
            )
            .then(
                if (selected) {
                    Modifier.border(2.dp, Color(0xFF00E5FF), RoundedCornerShape(16.dp))
                } else {
                    Modifier.border(
                        width = 1.dp,
                        brush = Brush.linearGradient(
                            colors = listOf(
                                Color(0xFF00E5FF).copy(alpha = 0.6f),
                                Color(0xFF7C4DFF).copy(alpha = 0.4f)
                            )
                        ),
                        shape = RoundedCornerShape(16.dp)
                    )
                }
            )
            .combinedClickable(
                enabled = onClick != null || onLongClick != null,
                onClick = { onClick?.invoke() },
                onLongClick = { onLongClick?.invoke() }
            )
            .padding(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Icon placeholder
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color(program.iconColor)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = program.name.take(2).uppercase().ifEmpty { "P" },
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = program.name,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
                Text(
                    text = program.developer,
                    fontSize = 12.sp,
                    color = Color.White.copy(alpha = 0.6f)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Status: ${program.status}",
                    fontSize = 12.sp,
                    color = Color(0xFF80DEEA)
                )
                Text(
                    text = "Trans: ${if (program.os == "linux") "Linux x86-64" else "Windows x64"} → ARMv9 NEON",
                    fontSize = 11.sp,
                    color = Color(0xFF00E5FF)
                )
            }

            // Play button bottom-right aligned
            if (onPlay != null) {
                IconButton(
                    onClick = onPlay,
                    modifier = Modifier
                        .align(Alignment.Bottom)
                        .size(40.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.PlayArrow,
                        contentDescription = "Play",
                        tint = Color(0xFF00E5FF),
                        modifier = Modifier.size(28.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun CreatorContent() {
    val messages = remember {
        mutableStateListOf(
            ChatMessage("0", "Creator ready. I can generate tools, patches, and extensions.\nTools: " +
                BuiltinTools.all.joinToString(", ") { it.name }, fromUser = false, status = MessageStatus.DONE)
        )
    }
    var input by remember { mutableStateOf("") }
    var thinking by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Column(Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.weight(1f),
            reverseLayout = true,
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(vertical = 8.dp)
        ) {
            if (thinking) {
                item {
                    ReceiptBubble("thinking…", MessageStatus.THINKING)
                }
            }
            items(messages.reversed()) { msg ->
                ChatBubble(msg)
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Message") },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF00E5FF),
                    unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White
                )
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = {
                    if (input.isBlank()) return@Button
                    val text = input
                    input = ""
                    messages.add(ChatMessage(System.currentTimeMillis().toString(), text, true, MessageStatus.SENT))
                    thinking = true
                    scope.launch {
                        val reply = withContext(Dispatchers.IO) {
                            CloudClient.chat(context, text, messages.toList())
                        }
                        thinking = false
                        messages.add(ChatMessage(
                            (System.currentTimeMillis() + 1).toString(),
                            reply, false, MessageStatus.DONE
                        ))
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00E5FF), contentColor = Color.Black)
            ) { Text("Send") }
        }
    }
}

@Composable
fun ChatBubble(msg: ChatMessage) {
    val align = if (msg.fromUser) Alignment.CenterEnd else Alignment.CenterStart
    val bg = if (msg.fromUser) Color(0xFF00E5FF) else Color(0xFF1A1A28)
    val fg = if (msg.fromUser) Color.Black else Color.White
    Box(Modifier.fillMaxWidth(), contentAlignment = align) {
        Column(
            Modifier
                .widthIn(max = 280.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(bg)
                .padding(10.dp)
        ) {
            Text(msg.text, color = fg, fontSize = 14.sp)
            Text(
                when (msg.status) {
                    MessageStatus.SENDING -> "sending"
                    MessageStatus.SENT -> "sent"
                    MessageStatus.THINKING -> "thinking"
                    MessageStatus.DONE -> "delivered"
                },
                color = fg.copy(alpha = 0.6f),
                fontSize = 10.sp
            )
        }
    }
}

@Composable
fun ReceiptBubble(text: String, status: MessageStatus) {
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.CenterStart) {
        Text(text, color = Color(0xFF80DEEA), fontSize = 12.sp, modifier = Modifier.padding(4.dp))
    }
}

@Composable
fun ExtensionsContent() {
    var subTab by remember { mutableIntStateOf(0) }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val installed = remember { mutableStateListOf<CatalogItem>() }
    val browse = remember { mutableStateListOf<CatalogItem>() }
    LaunchedEffect(subTab) {
        if (subTab == 1) {
            val items = withContext(Dispatchers.IO) { CatalogFetcher.fetch(context) }
            browse.clear()
            browse.addAll(items)
        }
    }

    Column(Modifier.fillMaxSize()) {
        TabRow(
            selectedTabIndex = subTab,
            containerColor = Color(0xFF0D0D14),
            contentColor = Color(0xFF00E5FF)
        ) {
            Tab(selected = subTab == 0, onClick = { subTab = 0 }, text = { Text("Installed") })
            Tab(selected = subTab == 1, onClick = { subTab = 1 }, text = { Text("Browse") })
        }
        Spacer(Modifier.height(12.dp))
        val list = if (subTab == 0) installed else browse
        if (list.isEmpty()) {
            Text(
                if (subTab == 0) "No extensions or patches installed." else "No items. Add a repository in Settings.",
                color = Color.White.copy(alpha = 0.6f),
                modifier = Modifier.padding(top = 24.dp)
            )
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(list) { item ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val file = ExtensionInstaller.download(context, item.downloadUrl, "${item.id}.${if (item.type == CatalogItemType.EXTENSION) "apk" else "patch"}")
                                        if (item.type == CatalogItemType.EXTENSION) {
                                            withContext(Dispatchers.Main) {
                                                ExtensionInstaller.installApk(context, file)
                                            }
                                        }
                                    } catch (e: Exception) {
                                        android.util.Log.e("NINE", "download failed", e)
                                        GuestLog.add("extensions: download failed: ${e.message}")
                                    }
                                }
                            },
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF12121C))
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Text(item.name, color = Color.White, fontWeight = FontWeight.Bold)
                            Text(
                                "${item.type.name.lowercase()} · ${item.version} · ${item.author}",
                                color = Color(0xFF80DEEA),
                                fontSize = 12.sp
                            )
                            Text(item.description, color = Color.White.copy(alpha = 0.6f), fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun LibraryContent(
    programs: List<LibraryProgram>,
    onPlay: (LibraryProgram) -> Unit,
    onRelink: (List<LibraryProgram>) -> Unit,
    onExport: (List<LibraryProgram>) -> Unit
) {
    // Long-press enters multi-select; FABs act on the selection
    val selected = remember { mutableStateListOf<String>() }
    val selectionMode = selected.isNotEmpty()

    Box(modifier = Modifier.fillMaxSize()) {
        if (programs.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(vertical = 48.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    "Library is empty",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color.White.copy(alpha = 0.8f)
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Imported programs are kept here permanently.\nLong-press a program to select and save or relink it.",
                    fontSize = 13.sp,
                    color = Color.White.copy(alpha = 0.5f),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 32.dp)
                )
            }
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                contentPadding = PaddingValues(bottom = 88.dp)
            ) {
                if (selectionMode) {
                    item {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                "${selected.size} selected",
                                fontSize = 12.sp,
                                color = Color(0xFF00E5FF)
                            )
                            Spacer(Modifier.weight(1f))
                            TextButton(onClick = { selected.clear() }) {
                                Text("Clear", fontSize = 12.sp, color = Color.White.copy(alpha = 0.7f))
                            }
                        }
                    }
                }
                items(programs, key = { it.id }) { p ->
                    ProgramCard(
                        program = p,
                        selected = p.id in selected,
                        onClick = {
                            if (selectionMode) {
                                if (!selected.remove(p.id)) selected.add(p.id)
                            } else {
                                onPlay(p)
                            }
                        },
                        onLongClick = {
                            if (!selected.remove(p.id)) selected.add(p.id)
                        },
                        onPlay = { onPlay(p) }
                    )
                }
            }
        }

        if (selectionMode) {
            Row(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                FloatingActionButton(
                    onClick = {
                        val targets = programs.filter { it.id in selected }
                        selected.clear()
                        if (targets.isNotEmpty()) onExport(targets)
                    },
                    containerColor = Color(0xFF7C4DFF),
                    contentColor = Color.White
                ) {
                    Icon(Icons.Default.Save, contentDescription = "Save programs to archive")
                }
                FloatingActionButton(
                    onClick = {
                        val targets = programs.filter { it.id in selected }
                        selected.clear()
                        if (targets.isNotEmpty()) onRelink(targets)
                    },
                    containerColor = Color(0xFF00E5FF),
                    contentColor = Color.Black
                ) {
                    Icon(Icons.Default.Link, contentDescription = "Relink to NINE ABI")
                }
            }
        }
    }
}

@Composable
fun LogsContent() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // Built-in Android "Save as" dialog (SAF CreateDocument)
    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val snapshot = GuestLog.lines.toList()
                val res = withContext(Dispatchers.IO) {
                    runCatching {
                        val os = context.contentResolver.openOutputStream(uri)
                            ?: error("cannot open stream")
                        os.use { it.write(snapshot.joinToString("\n").toByteArray()) }
                    }
                }
                res.onSuccess { GuestLog.info("logs saved (${snapshot.size} lines)") }
                    .onFailure { GuestLog.add("log save failed: ${it.message}") }
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        if (GuestLog.lines.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No logs yet", color = Color.White.copy(alpha = 0.6f))
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                items(GuestLog.lines) { line ->
                    Text(line, color = Color(0xFF80DEEA), fontSize = 12.sp)
                }
            }
        }

        FloatingActionButton(
            onClick = {
                val stamp = java.text.SimpleDateFormat(
                    "yyyyMMdd-HHmmss", java.util.Locale.US
                ).format(java.util.Date())
                saveLauncher.launch("nine-logs-$stamp.txt")
            },
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(16.dp),
            containerColor = Color(0xFF00E5FF),
            contentColor = Color.Black
        ) {
            Icon(Icons.Default.Save, contentDescription = "Save logs")
        }
    }
}
