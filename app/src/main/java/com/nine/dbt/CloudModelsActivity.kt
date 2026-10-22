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
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class CloudModelsActivity : ComponentActivity() {
    private val models = mutableStateListOf<CloudModel>()
    private var activeId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NineTheme {
                CloudListScreen(
                    models = models,
                    activeId = { activeId },
                    onBack = { finish() },
                    onAdd = { startActivity(Intent(this, AddCloudModelActivity::class.java)) },
                    onSelect = { m ->
                        AppStore.setActiveCloudId(this, m.id)
                        activeId = m.id
                    },
                    onEdit = { m ->
                        startActivity(Intent(this, AddCloudModelActivity::class.java).apply {
                            putExtra("id", m.id)
                            putExtra("modelId", m.modelId)
                            putExtra("url", m.url)
                            putExtra("apiKey", m.apiKey)
                        })
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        models.clear()
        models.addAll(AppStore.cloudModels(this))
        activeId = AppStore.activeCloudId(this)
    }
}

@OptIn(ExperimentalFoundationApi::class)
@androidx.compose.runtime.Composable
fun CloudListScreen(
    models: List<CloudModel>,
    activeId: () -> String?,
    onBack: () -> Unit,
    onAdd: () -> Unit,
    onSelect: (CloudModel) -> Unit,
    onEdit: (CloudModel) -> Unit
) {
    Column(Modifier.fillMaxSize().background(Color(0xFF0A0A12)).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.ArrowBack, "Back", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() })
            Spacer(Modifier.width(12.dp))
            Text("CLOUD MODELS", color = Color(0xFF00E5FF), fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Icon(Icons.Default.Add, "Add", tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onAdd() })
        }
        Spacer(Modifier.height(8.dp))
        Text("Tap to set active · Long-press to edit", color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp)
        Spacer(Modifier.height(12.dp))
        if (models.isEmpty()) {
            Text("No cloud models added.", color = Color.White.copy(alpha = 0.6f))
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(models) { m ->
                    val active = activeId() == m.id
                    Card(
                        Modifier.fillMaxWidth().combinedClickable(
                            onClick = { onSelect(m) },
                            onLongClick = { onEdit(m) }
                        ),
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (active) Color(0xFF003840) else Color(0xFF12121C)
                        )
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Text(m.modelId + if (active) "  · ACTIVE" else "", color = Color.White, fontWeight = FontWeight.Bold)
                            Text(m.url, color = Color(0xFF80DEEA), fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}
