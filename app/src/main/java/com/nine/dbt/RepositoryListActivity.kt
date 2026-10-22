package com.nine.dbt

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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

class RepositoryListActivity : ComponentActivity() {
    private val repos = androidx.compose.runtime.mutableStateListOf<Repository>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NineTheme {
                RepositoryListScreen(
                    repos = repos,
                    onBack = { finish() },
                    onAdd = { startActivity(Intent(this, AddRepositoryActivity::class.java)) },
                    onOpen = { repo ->
                        startActivity(Intent(this, AddRepositoryActivity::class.java).apply {
                            putExtra("id", repo.id)
                            putExtra("name", repo.name)
                            putExtra("url", repo.url)
                            putExtra("branch", repo.branch)
                        })
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        repos.clear()
        repos.addAll(AppStore.repositories(this))
    }
}

@Composable
fun RepositoryListScreen(
    repos: List<Repository>,
    onBack: () -> Unit,
    onAdd: () -> Unit,
    onOpen: (Repository) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0A0A12))
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Default.ArrowBack,
                contentDescription = "Back",
                tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onBack() }
            )
            Spacer(Modifier.width(12.dp))
            Text("REPOSITORIES", color = Color(0xFF00E5FF), fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Icon(
                Icons.Default.Add,
                contentDescription = "Add",
                tint = Color(0xFF00E5FF),
                modifier = Modifier.size(28.dp).clickable { onAdd() }
            )
        }
        Spacer(Modifier.height(16.dp))
        if (repos.isEmpty()) {
            Text("No repositories added.", color = Color.White.copy(alpha = 0.6f))
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(repos) { repo ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpen(repo) },
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF12121C))
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Text(repo.name, color = Color.White, fontWeight = FontWeight.Bold)
                            Text(repo.url, color = Color(0xFF80DEEA), fontSize = 12.sp)
                            Text("branch: ${repo.branch}", color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp)
                        }
                    }
                }
            }
        }
    }
}
