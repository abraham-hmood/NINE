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

class AddCloudModelActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val isEdit = intent.hasExtra("id")
        setContent {
            NineTheme {
                AddCloudScreen(
                    initialId = intent.getStringExtra("modelId") ?: "",
                    initialUrl = intent.getStringExtra("url") ?: "",
                    initialKey = intent.getStringExtra("apiKey") ?: "",
                    isEdit = isEdit,
                    onBack = { finish() },
                    onSave = { id, url, key ->
                        val models = AppStore.cloudModels(this)
                        val existing = intent.getStringExtra("id")
                        if (existing != null) {
                            val idx = models.indexOfFirst { it.id == existing }
                            if (idx >= 0) models[idx] = CloudModel(existing, id, url, key)
                        } else {
                            models += CloudModel(System.currentTimeMillis().toString(), id, url, key)
                        }
                        AppStore.saveCloudModels(this, models)
                        finish()
                    },
                    onDelete = {
                        intent.getStringExtra("id")?.let { AppStore.deleteCloud(this, it) }
                        finish()
                    }
                )
            }
        }
    }
}

@Composable
fun AddCloudScreen(
    initialId: String, initialUrl: String, initialKey: String,
    isEdit: Boolean, onBack: () -> Unit,
    onSave: (String, String, String) -> Unit,
    onDelete: () -> Unit
) {
    var modelId by remember { mutableStateOf(initialId) }
    var url by remember { mutableStateOf(initialUrl) }
    var key by remember { mutableStateOf(initialKey) }
    Column(Modifier.fillMaxSize().background(Color(0xFF0A0A12)).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.ArrowBack, "Back", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() })
            Spacer(Modifier.width(12.dp))
            Text(if (isEdit) "EDIT MODEL" else "ADD MODEL", color = Color(0xFF00E5FF), fontSize = 22.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(24.dp))
        NineField(modelId, { modelId = it }, "Model ID (e.g. gpt-4o)")
        Spacer(Modifier.height(12.dp))
        NineField(url, { url = it }, "Model URL")
        Spacer(Modifier.height(12.dp))
        NineField(key, { key = it }, "API Key")
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = { onSave(modelId, url, key) },
            enabled = modelId.isNotBlank() && url.isNotBlank(),
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00E5FF), contentColor = Color.Black)
        ) { Text("SAVE", fontWeight = FontWeight.Bold) }
        if (isEdit) {
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = onDelete,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE53935), contentColor = Color.White)
            ) { Text("DELETE", fontWeight = FontWeight.Bold) }
        }
    }
}

@Composable
fun NineField(value: String, onChange: (String) -> Unit, label: String) {
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) },
        modifier = Modifier.fillMaxWidth(),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Color(0xFF00E5FF),
            unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
            focusedTextColor = Color.White, unfocusedTextColor = Color.White
        )
    )
}
