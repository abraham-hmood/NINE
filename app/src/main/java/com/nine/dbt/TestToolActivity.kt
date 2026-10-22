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
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class TestToolActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val name = intent.getStringExtra("name") ?: "tool"
        val params = intent.getStringExtra("params")?.split(",")?.filter { it.isNotBlank() } ?: emptyList()
        setContent {
            NineTheme {
                TestToolScreen(name, params, onBack = { finish() })
            }
        }
    }
}

@Composable
fun TestToolScreen(name: String, params: List<String>, onBack: () -> Unit) {
    val context = LocalContext.current
    val values = remember { params.associateWith { mutableStateOf("") } }
    var output by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().background(Color(0xFF0A0A12)).padding(16.dp).verticalScroll(rememberScrollState())
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.ArrowBack, "Back", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() })
            Spacer(Modifier.width(12.dp))
            Text("TEST: $name", color = Color(0xFF00E5FF), fontSize = 20.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(16.dp))
        params.forEach { p ->
            NineField(values[p]?.value ?: "", { values[p]?.value = it }, p)
            Spacer(Modifier.height(8.dp))
        }
        Button(
            onClick = {
                val args = params.associateWith { values[it]?.value ?: "" }
                output = ToolExecutor.run(context, name, args)
            },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00E5FF), contentColor = Color.Black)
        ) { Text("RUN", fontWeight = FontWeight.Bold) }
        Spacer(Modifier.height(16.dp))
        Text("OUTPUT", color = Color(0xFF80DEEA), fontSize = 12.sp)
        Spacer(Modifier.height(4.dp))
        Text(output.ifEmpty { "(no output yet)" }, color = Color.White, fontSize = 14.sp)
    }
}
