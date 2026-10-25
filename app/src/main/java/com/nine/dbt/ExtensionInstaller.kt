package com.nine.dbt

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings
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

    /**
     * Whether the app may offer APK installs at all. Missing "Install unknown
     * apps" makes PackageInstaller.createSession throw SecurityException, so
     * callers check first and surface the real cause instead of an empty
     * failure line.
     */
    fun canRequestInstall(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O || ctx.packageManager.canRequestPackageInstalls()

    /** Opens this app's "Install unknown apps" settings page. */
    fun openInstallPermissionSettings(ctx: Context) {
        try {
            val intent = Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${ctx.packageName}")
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(intent)
        } catch (t: Throwable) {
            GuestLog.add("light shell: could not open install-permission settings: ${t.message}")
        }
    }

    fun installApk(ctx: Context, apk: File) {
        val installer = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        val sessionId = installer.createSession(params)
        val session = installer.openSession(sessionId)
        session.use {
            apk.inputStream().use { input ->
                it.openWrite("base.apk", 0, apk.length()).use { out ->
                    input.copyTo(out)
                    it.fsync(out)
                }
            }
            val callback = PendingIntent.getBroadcast(
                ctx, sessionId,
                Intent(ctx, InstallResultReceiver::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            )
            it.commit(callback.intentSender)
        }
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
        val pkg = intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME)
        android.util.Log.i("NINE", "Install status=$status pkg=$pkg $msg")

        // Every non-privileged install hands back STATUS_PENDING_USER_ACTION
        // first: the session is live and waiting for the system installer UI.
        // That status carries no status message, so treating it as a failure
        // aborted each shell install with a blank reason. Launch the UI and
        // let the real result arrive on this same PendingIntent.
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            val confirm = confirmIntent(intent)
            val launched = confirm != null && try {
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(confirm)
                GuestLog.info(
                    "light shell: waiting for install confirmation" +
                        (pkg?.let { " ($it)" } ?: "")
                )
                true
            } catch (t: Throwable) {
                GuestLog.add("light shell: could not open installer UI: ${t.message}")
                false
            }
            if (!launched) {
                // Nothing will ever report this session back, so release the
                // queue instead of letting it stall behind a dead prompt.
                ShellInstallQueue.onResult(
                    context, pkg, false, "installer confirmation unavailable"
                )
            }
            return
        }

        ShellInstallQueue.onResult(
            context, pkg, status == PackageInstaller.STATUS_SUCCESS, describe(status, msg)
        )
    }

    private fun confirmIntent(intent: Intent): Intent? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_INTENT)
        }

    /** Maps a PackageInstaller status to a readable reason for the log. */
    private fun describe(status: Int, msg: String): String {
        val name = when (status) {
            PackageInstaller.STATUS_SUCCESS -> "SUCCESS"
            PackageInstaller.STATUS_FAILURE -> "FAILURE"
            PackageInstaller.STATUS_FAILURE_BLOCKED -> "BLOCKED"
            PackageInstaller.STATUS_FAILURE_ABORTED -> "CANCELLED"
            PackageInstaller.STATUS_FAILURE_INVALID -> "INVALID_APK"
            PackageInstaller.STATUS_FAILURE_CONFLICT -> "CONFLICT"
            PackageInstaller.STATUS_FAILURE_STORAGE -> "STORAGE"
            PackageInstaller.STATUS_FAILURE_INCOMPATIBLE -> "INCOMPATIBLE"
            else -> "STATUS_$status"
        }
        return if (msg.isBlank()) name else "$name: $msg"
    }
}
