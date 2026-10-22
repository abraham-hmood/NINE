package com.nine.dbt

import android.content.Context
import org.json.JSONObject
import java.net.URL

object CatalogFetcher {
    fun fetch(ctx: Context): List<CatalogItem> {
        val repos = AppStore.repositories(ctx)
        val items = mutableListOf<CatalogItem>()
        for (repo in repos) {
            val raw = githubRaw(repo.url, repo.branch, "nine-catalog.json") ?: continue
            try {
                val json = JSONObject(raw)
                val arr = json.getJSONArray("items")
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    items += CatalogItem(
                        id = o.getString("id"),
                        name = o.getString("name"),
                        author = o.optString("author", ""),
                        description = o.optString("description", ""),
                        type = if (o.optString("type") == "patch") CatalogItemType.PATCH else CatalogItemType.EXTENSION,
                        downloadUrl = o.getString("downloadUrl"),
                        version = o.optString("version", "0"),
                        repositoryId = repo.id
                    )
                }
            } catch (_: Exception) {}
        }
        return items
    }

    private fun githubRaw(repoUrl: String, branch: String, path: String): String? {
        // https://github.com/user/repo -> https://raw.githubusercontent.com/user/repo/branch/path
        val m = Regex("""github\.com/([^/]+)/([^/]+)""").find(repoUrl) ?: return null
        val raw = "https://raw.githubusercontent.com/${m.groupValues[1]}/${m.groupValues[2].removeSuffix(".git")}/$branch/$path"
        return try {
            URL(raw).openStream().bufferedReader().readText()
        } catch (_: Exception) {
            null
        }
    }
}
