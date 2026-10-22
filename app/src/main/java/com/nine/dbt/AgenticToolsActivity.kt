package com.nine.dbt

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class AgenticToolsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NineTheme {
                val tools = remember {
                    mutableStateListOf<AgenticTool>().apply {
                        addAll(BuiltinTools.all)
                        addAll(AppStore.customTools(this@AgenticToolsActivity))
                    }
                }
                ToolsListScreen(
                    tools = tools,
                    onBack = { finish() },
                    onAdd = { startActivity(Intent(this, AddToolActivity::class.java)) },
                    onEdit = { t ->
                        startActivity(Intent(this, AddToolActivity::class.java).apply {
                            putExtra("id", t.id)
                            putExtra("name", t.name)
                            putExtra("code", t.code)
                        })
                    },
                    onTest = { t ->
                        startActivity(Intent(this, TestToolActivity::class.java).apply {
                            putExtra("name", t.name)
                            putExtra("params", t.params.joinToString(",") { it.name })
                        })
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ToolsListScreen(
    tools: List<AgenticTool>,
    onBack: () -> Unit,
    onAdd: () -> Unit,
    onEdit: (AgenticTool) -> Unit,
    onTest: (AgenticTool) -> Unit
) {
    Column(Modifier.fillMaxSize().background(Color(0xFF0A0A12)).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.ArrowBack, "Back", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() })
            Spacer(Modifier.width(12.dp))
            Text("AGENTIC TOOLS", color = Color(0xFF00E5FF), fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Icon(Icons.Default.Add, "Add", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onAdd() })
        }
        Spacer(Modifier.height(8.dp))
        Text("Tap to test · Long-press to edit", color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp)
        Spacer(Modifier.height(12.dp))
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(tools) { t ->
                Card(
                    Modifier.fillMaxWidth().combinedClickable(
                        onClick = { onTest(t) },
                        onLongClick = { onEdit(t) }
                    ),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF12121C))
                ) {
                    Column(Modifier.padding(12.dp)) {
                        Text(t.name, color = Color.White, fontWeight = FontWeight.Bold)
                        Text(
                            if (t.isBuiltin) "builtin · ${t.params.size} params" else "custom · ${t.params.size} params",
                            color = Color(0xFF80DEEA), fontSize = 12.sp
                        )
                    }
                }
            }
        }
    }
}
