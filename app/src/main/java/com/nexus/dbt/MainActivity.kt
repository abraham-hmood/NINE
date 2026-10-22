package com.nexus.dbt

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.LibraryBooks
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.*
import androidx.compose.runtime.*
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
            NexusTheme {
                NexusApp()
            }
        }
    }
}

@Composable
fun NexusTheme(content: @Composable () -> Unit) {
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

data class TranslatedProgram(
    val name: String,
    val developer: String,
    val status: String,
    val sourceArch: String,
    val targetArch: String,
    val iconColor: Color
)

@Composable
fun NexusApp() {
    var selectedTab by remember { mutableIntStateOf(0) }
    // Empty by default — real programs will be loaded from storage later
    val programs = remember { mutableStateListOf<TranslatedProgram>() }

    Scaffold(
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
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 24.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "NEXUS",
                        fontSize = 32.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF00E5FF),
                        letterSpacing = 2.sp
                    )
                    Text(
                        text = "DYNAMIC BINARY TRANSLATION",
                        fontSize = 11.sp,
                        color = Color(0xFF80DEEA),
                        letterSpacing = 1.sp
                    )
                }
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = "Settings",
                    tint = Color(0xFF00E5FF),
                    modifier = Modifier.size(28.dp)
                )
            }

            Text(
                text = "RECENTLY TRANSLATED PROGRAMS",
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                color = Color.White.copy(alpha = 0.7f),
                modifier = Modifier.padding(top = 16.dp, bottom = 4.dp)
            )
            Text(
                text = "Active: x86-64 → ARMv9 NEON",
                fontSize = 12.sp,
                color = Color(0xFF00E5FF),
                modifier = Modifier.padding(bottom = 12.dp)
            )

            when (selectedTab) {
                0 -> HomeContent(programs)
                1 -> LibraryContent()
                2 -> LogsContent()
            }
        }
    }
}

@Composable
fun HomeContent(programs: List<TranslatedProgram>) {
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
                onClick = { /* Load new program */ },
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
            items(programs) { program ->
                ProgramCard(program)
            }
            item {
                Button(
                    onClick = { /* Load new program */ },
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

@Composable
fun ProgramCard(program: TranslatedProgram) {
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
            .border(
                width = 1.dp,
                brush = Brush.linearGradient(
                    colors = listOf(Color(0xFF00E5FF).copy(alpha = 0.6f), Color(0xFF7C4DFF).copy(alpha = 0.4f))
                ),
                shape = RoundedCornerShape(16.dp)
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
                    .background(program.iconColor),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = program.name.take(2).uppercase(),
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
                    text = "Trans: ${program.sourceArch} → ${program.targetArch}",
                    fontSize = 11.sp,
                    color = Color(0xFF00E5FF)
                )
            }

            // Play button bottom-right aligned
            IconButton(
                onClick = { /* Launch */ },
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

@Composable
fun LibraryContent() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text("Library — All translated programs", color = Color.White.copy(alpha = 0.6f))
    }
}

@Composable
fun LogsContent() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text("Translation logs will appear here", color = Color.White.copy(alpha = 0.6f))
    }
}
