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

class AddRepositoryActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val existingId = intent.getStringExtra("id")
        val existingName = intent.getStringExtra("name") ?: ""
        val existingUrl = intent.getStringExtra("url") ?: ""
        val existingBranch = intent.getStringExtra("branch") ?: "main"
        setContent {
            NineTheme {
                AddRepositoryScreen(
                    initialName = existingName,
                    initialUrl = existingUrl,
                    initialBranch = existingBranch,
                    isEdit = existingId != null,
                    onBack = { finish() },
                    onSave = { name, url, branch ->
                        val repos = AppStore.repositories(this)
                        val existing = intent.getStringExtra("id")
                        if (existing != null) {
                            val idx = repos.indexOfFirst { it.id == existing }
                            if (idx >= 0) repos[idx] = Repository(existing, name, url, branch)
                            else repos += Repository(existing, name, url, branch)
                        } else {
                            repos += Repository(System.currentTimeMillis().toString(), name, url, branch)
                        }
                        AppStore.saveRepositories(this, repos)
                        finish()
                    }
                )
            }
        }
    }
}

@Composable
fun AddRepositoryScreen(
    initialName: String,
    initialUrl: String,
    initialBranch: String,
    isEdit: Boolean,
    onBack: () -> Unit,
    onSave: (String, String, String) -> Unit
) {
    var name by remember { mutableStateOf(initialName) }
    var url by remember { mutableStateOf(initialUrl) }
    var branch by remember { mutableStateOf(initialBranch) }

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
            Text(
                if (isEdit) "EDIT REPOSITORY" else "ADD REPOSITORY",
                color = Color(0xFF00E5FF),
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold
            )
        }
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text("Name") },
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFF00E5FF),
                unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White
            )
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = url,
            onValueChange = { url = it },
            label = { Text("GitHub URL") },
            placeholder = { Text("https://github.com/user/repo") },
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFF00E5FF),
                unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White
            )
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = branch,
            onValueChange = { branch = it },
            label = { Text("Branch") },
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFF00E5FF),
                unfocusedBorderColor = Color.White.copy(alpha = 0.3f),
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White
            )
        )
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = { onSave(name, url, branch) },
            enabled = name.isNotBlank() && url.contains("github.com"),
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF00E5FF),
                contentColor = Color.Black
            )
        ) {
            Text(if (isEdit) "SAVE" else "ADD", fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "GitHub repositories are supported. The catalog is read from a nine-catalog.json (or releases) in the repo.",
            color = Color.White.copy(alpha = 0.5f),
            fontSize = 12.sp
        )
    }
}
