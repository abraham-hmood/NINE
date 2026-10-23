package com.nine.dbt

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat

data class TutorialStep(val title: String, val body: String, val tab: Int?)

val tutorialSteps = listOf(
    TutorialStep("Welcome to 9", "NINE translates x86-64 programs to run on this ARM device. This tour covers every tab and setting.", null),
    TutorialStep("Home", "Translated programs appear here. Tap LOAD NEW PROGRAM to add one. Each card shows name, developer, status, and the architecture translation.", 0),
    TutorialStep("Library", "Your full library of translated programs lives here.", 1),
    TutorialStep("Logs", "Translation, loader, and linker logs. Use this when something fails.", 2),
    TutorialStep("Extensions", "Installed and Browse. Extensions are APKs; patches are .patch files from your repositories.", 3),
    TutorialStep("Creator", "Chat with an AI to build tools, extensions, and patches. It can call search_web, file tools, compile_extension, compile_patch, and add_tool.", 4),
    TutorialStep("Settings", "Tap the gear. Use local AI switches between on-device and cloud. Cloud Models, Agentic Tools, Browse Models, and Import Local LLM live here.", null),
    TutorialStep("Models", "Browse Hugging Face and GitHub. One quantization downloads immediately. Several open a radio list. Downloads run in the background.", null),
    TutorialStep("Permissions", "Next we will ask for the permissions NINE needs, and explain each one.", null)
)

@Composable
fun TutorialOverlay(
    activity: ComponentActivity,
    onTab: (Int) -> Unit,
    onDone: () -> Unit
) {
    var step by remember { mutableIntStateOf(0) }
    var showPermWhy by remember { mutableStateOf(false) }
    val s = tutorialSteps[step]

    LaunchedEffect(step) { s.tab?.let(onTab) }

    Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.72f)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().padding(16.dp).background(Color(0xFF12121C), RoundedCornerShape(16.dp)).padding(16.dp)
        ) {
            Text(s.title, color = Color(0xFF00E5FF), fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Text(s.body, color = Color.White, fontSize = 14.sp)
            Spacer(Modifier.height(16.dp))
            Row {
                TextButton(onClick = { showPermWhy = true }) { Text("Skip tutorial") }
                Spacer(Modifier.weight(1f))
                if (step > 0) TextButton(onClick = { step-- }) { Text("Back") }
                Button(
                    onClick = {
                        if (step < tutorialSteps.lastIndex) step++
                        else showPermWhy = true
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00E5FF), contentColor = Color.Black)
                ) { Text(if (step < tutorialSteps.lastIndex) "Next" else "Permissions") }
            }
        }
    }

    if (showPermWhy) {
        AlertDialog(
            onDismissRequest = {},
            title = { Text("Permissions") },
            text = {
                Text(
                    "Notifications: show download progress in the background.\n\n" +
                    "Install packages: install extensions and self-patches you approve.\n\n" +
                    "Storage: import local .gguf / .tflite models from your files.\n\n" +
                    "Internet is required to browse models and call cloud AIs."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showPermWhy = false
                    requestPermissions(activity)
                    onDone()
                }) { Text("Continue") }
            }
        )
    }
}

private fun requestPermissions(activity: ComponentActivity) {
    val needed = mutableListOf<String>()
    if (Build.VERSION.SDK_INT >= 33 &&
        ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
        needed += Manifest.permission.POST_NOTIFICATIONS
    }
    if (Build.VERSION.SDK_INT <= 32 &&
        ContextCompat.checkSelfPermission(activity, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
        needed += Manifest.permission.READ_EXTERNAL_STORAGE
    }
    // All-files access: light-shell APKs are saved to /sdcard/NINE/shells.
    // MANAGE_EXTERNAL_STORAGE cannot be requested through the runtime dialog —
    // jump straight to the system All-files-access screen.
    if (Build.VERSION.SDK_INT >= 30 && !android.os.Environment.isExternalStorageManager()) {
        try {
            activity.startActivity(
                android.content.Intent(
                    android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    android.net.Uri.parse("package:${activity.packageName}")
                )
            )
        } catch (_: Throwable) {
            try {
                activity.startActivity(
                    android.content.Intent(android.provider.Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                )
            } catch (_: Throwable) {}
        }
    }
    if (needed.isEmpty()) return
    activity.activityResultRegistry.register(
        "nine_perms",
        ActivityResultContracts.RequestMultiplePermissions()
    ) { }.launch(needed.toTypedArray())
}
