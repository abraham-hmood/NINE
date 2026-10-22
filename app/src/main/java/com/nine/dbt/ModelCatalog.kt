package com.nine.dbt

data class ModelQuant(val label: String, val url: String, val sizeMb: Long)
data class RemoteModel(
    val name: String,
    val author: String,
    val type: String,          // gguf, tflite, task, ...
    val quants: List<ModelQuant>,
    val sizeMb: Long,
    val source: String,        // huggingface / github
    val runsOnCpu: Boolean = true,
    val runsOnNpu: Boolean = false,
    val minRamMb: Long = 0,
    val supportsTools: Boolean = false
)

object ModelCatalog {
    fun search(query: String): List<RemoteModel> {
        val hf = searchHf(query)
        val gh = searchGh(query)
        return hf + gh
    }

    private fun searchHf(query: String): List<RemoteModel> {
        return try {
            val url = java.net.URL("https://huggingface.co/api/models?search=" +
                java.net.URLEncoder.encode(query.ifBlank { "gguf" }, "UTF-8") +
                "&filter=text-generation&limit=30")
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.setRequestProperty("User-Agent", "NINE/1.0")
            conn.connectTimeout = 15000
            val body = conn.inputStream.bufferedReader().readText()
            conn.disconnect()
            parseHf(body)
        } catch (_: Exception) { emptyList() }
    }

    private fun parseHf(body: String): List<RemoteModel> {
        val out = mutableListOf<RemoteModel>()
        val arr = org.json.JSONArray(body)
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val id = o.optString("id", "")
            val author = id.substringBefore("/")
            val name = id.substringAfter("/")
            val siblings = o.optJSONArray("siblings")
            val quants = mutableListOf<ModelQuant>()
            var type = "gguf"
            if (siblings != null) {
                for (j in 0 until siblings.length()) {
                    val fn = siblings.getJSONObject(j).optString("rfilename", "")
                    val ext = fn.substringAfterLast('.', "")
                    if (ext in listOf("gguf", "tflite", "task", "bin", "onnx")) {
                        type = ext
                        val label = fn.substringAfterLast('/').substringBeforeLast('.')
                        quants += ModelQuant(label, "https://huggingface.co/$id/resolve/main/$fn", 0)
                    }
                }
            }
            val tags = o.optJSONArray("tags")
            val tagList = if (tags != null) (0 until tags.length()).map { tags.getString(it).lowercase() } else emptyList()
            val pipeline = o.optString("pipeline_tag", "").lowercase()
            val supportsTools = tagList.any { it.contains("tool") || it.contains("function") || it.contains("agent") }
                || name.contains("tool", true) || name.contains("function", true)
                || pipeline.contains("tool")
            if (quants.isEmpty()) continue
            out += RemoteModel(name, author, type, quants, quants.size * 500L, "huggingface",
                runsOnCpu = true, minRamMb = 2048, supportsTools = supportsTools)
        }
        return out
    }

    private fun searchGh(query: String): List<RemoteModel> {
        // GitHub repo search returns HTML pages, not GGUF files. Skip it so we
        // never offer a non-file URL as a download.
        return emptyList()
    }
}
