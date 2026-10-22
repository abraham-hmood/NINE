package com.nine.dbt

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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

class AddToolActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val isEdit = intent.hasExtra("id")
        setContent {
            NineTheme {
                AddToolScreen(
                    initialName = intent.getStringExtra("name") ?: "",
                    initialCode = intent.getStringExtra("code") ?: "",
                    isEdit = isEdit,
                    onBack = { finish() },
                    onSave = { name, code ->
                        val tools = AppStore.customTools(this)
                        val existing = intent.getStringExtra("id")
                        val params = Regex("""fun\s+\w+\s*\(([^)]*)\)""")
                            .find(code)?.groupValues?.getOrNull(1)
                            ?.split(",")?.map { it.trim().substringBefore(":").substringBefore("=").trim() }
                            ?.filter { it.isNotEmpty() }?.map { ToolParam(it) } ?: emptyList()
                        if (existing != null && tools.any { it.id == existing }) {
                            val idx = tools.indexOfFirst { it.id == existing }
                            tools[idx] = AgenticTool(existing, name, code, params, false)
                        } else {
                            tools += AgenticTool(System.currentTimeMillis().toString(), name, code, params, false)
                        }
                        AppStore.saveCustomTools(this, tools)
                        finish()
                    }
                )
            }
        }
    }
}

@Composable
fun AddToolScreen(
    initialName: String, initialCode: String, isEdit: Boolean,
    onBack: () -> Unit, onSave: (String, String) -> Unit
) {
    var name by remember { mutableStateOf(initialName) }
    var code by remember { mutableStateOf(initialCode) }
    Column(Modifier.fillMaxSize().background(Color(0xFF0A0A12)).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.ArrowBack, "Back", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() })
            Spacer(Modifier.width(12.dp))
            Text(if (isEdit) "EDIT TOOL" else "ADD TOOL", color = Color(0xFF00E5FF), fontSize = 22.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(24.dp))
        NineField(name, { name = it }, "Tool name")
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = code, onValueChange = { code = it }, label = { Text("Tool code") },
            modifier = Modifier.fillMaxWidth().height(220.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFF00E5FF),
                unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
                focusedTextColor = Color.White, unfocusedTextColor = Color.White
            )
        )
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = { onSave(name, code) },
            enabled = name.isNotBlank(),
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00E5FF), contentColor = Color.Black)
        ) { Text("SAVE", fontWeight = FontWeight.Bold) }
    }
}
