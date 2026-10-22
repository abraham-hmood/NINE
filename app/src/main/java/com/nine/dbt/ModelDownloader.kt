package com.nine.dbt

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.compose.runtime.mutableStateMapOf
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import java.io.File
import java.net.URL

data class DownloadProgress(val modelKey: String, val percent: Int, val done: Boolean, val path: String? = null)

object ModelDownloader {
    private const val CHANNEL = "nine_downloads"
    // Survives leaving the activity. Keyed by model name.
    val progress = mutableStateMapOf<String, DownloadProgress>()

    fun ensureChannel(ctx: Context) {
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "Model downloads", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    fun download(ctx: Context, model: RemoteModel, quant: ModelQuant) {
        ensureChannel(ctx)
        val key = model.name
        val id = key.hashCode()
        progress[key] = DownloadProgress(key, 0, false)
        Thread {
            try {
                notify(ctx, id, "Downloading ${model.name}", "Starting…", 0, true)
                val dir = File(ctx.filesDir, "models").also { it.mkdirs() }
                val out = File(dir, "${model.name}-${quant.label}.${model.type}")
                val conn = openFollowingRedirects(quant.url)
                val total = conn.contentLengthLong.coerceAtLeast(1)
                val type = conn.contentType ?: ""
                if (type.contains("text/html")) {
                    progress[key] = DownloadProgress(key, 0, true, null)
                    notify(ctx, id, "Download failed", "Got HTML, not a model file", 0, false)
                    AppLog.e("download", "HTML response for ${quant.url}")
                    GuestLog.add("download: HTML response for ${quant.url}")
                    return@Thread
                }
                conn.getInputStream().use { input ->
                    out.outputStream().use { output ->
                        val buf = ByteArray(64 * 1024)
                        var read = 0L
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            output.write(buf, 0, n)
                            read += n
                            val pct = ((read * 100) / total).toInt().coerceIn(0, 100)
                            progress[key] = DownloadProgress(key, pct, false)
                            notify(ctx, id, "Downloading ${model.name}", "$pct%", pct, true)
                        }
                    }
                }
                // Validate before importing.
                val magic = out.inputStream().use { it.readNBytes(4) }
                val okMagic = when (model.type) {
                    "gguf" -> String(magic) == "GGUF"
                    else -> magic.isNotEmpty()
                }
                if (!okMagic) {
                    out.delete()
                    progress[key] = DownloadProgress(key, 0, true, null)
                    notify(ctx, id, "Download failed", "Not a valid ${model.type}", 0, false)
                    AppLog.e("download", "Bad magic for ${out.name}: ${magic.joinToString { "%02x".format(it) }}")
                    GuestLog.add("download: bad magic for ${out.name}: ${magic.joinToString { "%02x".format(it) }}")
                    return@Thread
                }
                val existing = AppStore.localModels(ctx).toMutableList()
                if (out.absolutePath !in existing) existing += out.absolutePath
                AppStore.saveLocalModels(ctx, existing)
                AppStore.setLocalModelUri(ctx, out.absolutePath)
                progress[key] = DownloadProgress(key, 100, true, out.absolutePath)
                notify(ctx, id, "Imported ${model.name}", out.name, 100, false)
            } catch (e: Exception) {
                progress[key] = DownloadProgress(key, 0, true, null)
                notify(ctx, id, "Download failed", e.message ?: "error", 0, false)
                AppLog.e("download", "Failed ${model.name}", e)
                GuestLog.add("download: failed ${model.name}: ${e.message}")
            }
        }.start()
    }

    private fun openFollowingRedirects(url: String): java.net.HttpURLConnection {
        var current = url
        var last: java.net.HttpURLConnection? = null
        for (i in 0 until 5) {
            val conn = URL(current).openConnection() as java.net.HttpURLConnection
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("User-Agent", "NINE/1.0")
            conn.connectTimeout = 20000
            val code = conn.responseCode
            if (code in 300..399) {
                val loc = conn.getHeaderField("Location")
                conn.disconnect()
                if (loc == null) break
                current = if (loc.startsWith("http")) loc else URL(URL(current), loc).toString()
            } else {
                return conn
            }
            last = null
        }
        return URL(current).openConnection() as java.net.HttpURLConnection
    }

    private fun notify(ctx: Context, id: Int, title: String, text: String, progressPct: Int, ongoing: Boolean) {
        val b = NotificationCompat.Builder(ctx, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(ongoing)
            .setOnlyAlertOnce(true)
        if (ongoing) b.setProgress(100, progressPct, progressPct == 0)
        try { NotificationManagerCompat.from(ctx).notify(id, b.build()) } catch (_: SecurityException) {}
    }
}
