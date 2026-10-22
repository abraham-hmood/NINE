package com.nine.dbt

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import java.io.File
import java.net.URL

object ExtensionInstaller {
    fun download(ctx: Context, url: String, name: String): File {
        val dir = File(ctx.cacheDir, "downloads").also { it.mkdirs() }
        val out = File(dir, name)
        URL(url).openStream().use { input ->
            out.outputStream().use { input.copyTo(it) }
        }
        return out
    }

    fun installApk(ctx: Context, apk: File) {
        val installer = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        val sessionId = installer.createSession(params)
        val session = installer.openSession(sessionId)
        apk.inputStream().use { input ->
            session.openWrite("base.apk", 0, apk.length()).use { out ->
                input.copyTo(out)
                session.fsync(out)
            }
        }
        val callback = PendingIntent.getBroadcast(
            ctx, sessionId,
            Intent(ctx, InstallResultReceiver::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )
        session.commit(callback.intentSender)
        session.close()
    }

    fun applyPatch(ctx: Context, patchFile: File, baseText: String): String {
        // Unified diff apply (simple +/ - line model)
        val lines = baseText.lines().toMutableList()
        var cursor = 0
        patchFile.readLines().forEach { line ->
            when {
                line.startsWith("+") && !line.startsWith("+++") -> {
                    lines.add(cursor, line.removePrefix("+"))
                    cursor++
                }
                line.startsWith("-") && !line.startsWith("---") -> {
                    if (cursor < lines.size) lines.removeAt(cursor)
                }
                line.startsWith("@@") -> cursor = 0
                else -> if (cursor < lines.size) cursor++
            }
        }
        return lines.joinToString("\n")
    }
}

class InstallResultReceiver : android.content.BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
        android.util.Log.i("NINE", "Install status=$status $msg")
    }
}
