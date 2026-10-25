package com.nine.dbt

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.concurrent.Executors

/** A successfully installed shell the user may want to launch. */
data class ShellRunRequest(
    val packageName: String,
    val programName: String
)

/**
 * UI-facing shell events. The install result arrives in a broadcast receiver,
 * which has no window, so the request to run a freshly installed shell is
 * published here and the Compose UI turns it into a dialog.
 */
object ShellEvents {
    var pendingRun by mutableStateOf<ShellRunRequest?>(null)

    /** Launches an installed shell's launcher activity. Returns false if it is not resolvable yet. */
    fun launch(context: Context, request: ShellRunRequest): Boolean {
        val intent = context.packageManager.getLaunchIntentForPackage(request.packageName)
        if (intent == null) {
            GuestLog.add(
                "light shell: ${request.packageName} is not launchable yet " +
                    "(install may still be settling)"
            )
            return false
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return try {
            context.startActivity(intent)
            GuestLog.info("light shell: launched ${request.packageName}")
            true
        } catch (t: Throwable) {
            GuestLog.add("light shell: launch failed: ${t.message}")
            false
        }
    }
}

/**
 * Installs built light shells one at a time.
 *
 * Android shows a single package-installer prompt at a time; committing every
 * session at once means all but the first sit behind the system UI (and the
 * per-package VHD grants race). The queue commits one session, waits for
 * [InstallResultReceiver] to report it, grants that package its VHD, then
 * starts the next one. All state lives on a single worker thread.
 */
object ShellInstallQueue {
    private data class Pending(
        val program: LibraryProgram,
        val apk: java.io.File,
        val packageName: String
    )

    private val worker = Executors.newSingleThreadExecutor { r ->
        Thread(r, "nine-shell-install").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())

    private val queue = ArrayDeque<Pending>()
    private var total = 0
    private var started = 0
    private var active: Pending? = null
    private var appContext: Context? = null

    fun start(context: Context, builds: List<LightShellPackager.ShellBuild>) {
        val ctx = context.applicationContext
        worker.execute {
            appContext = ctx
            queue.clear()
            builds.forEach { b ->
                queue.addLast(Pending(b.program, b.apk, b.packageName))
            }
            total = builds.size
            started = 0
            active = null
            GuestLog.info("light shells: ${builds.size} queued for install")
            installNext()
        }
    }

    private fun installNext() {
        val ctx = appContext ?: return
        val next = queue.removeFirstOrNull()
        if (next == null) {
            active = null
            return
        }
        // Without "Install unknown apps" createSession throws SecurityException
        // and the whole batch is pointless: say why once, open the settings
        // page, and drop the queue instead of reporting each item separately.
        if (!ExtensionInstaller.canRequestInstall(ctx)) {
            queue.clear()
            active = null
            GuestLog.add(
                "light shell: install blocked — allow \"Install unknown apps\" for NINE, " +
                    "then relink"
            )
            main.post { ExtensionInstaller.openInstallPermissionSettings(ctx) }
            return
        }
        active = next
        started++
        LightShellPackager.rememberVhdFor(ctx, next.packageName)
        GuestLog.info(
            "light shells: installing ${next.program.name} " +
                "($started/$total, ${next.packageName})"
        )
        try {
            ExtensionInstaller.installApk(ctx, next.apk)
        } catch (t: Throwable) {
            GuestLog.add(
                "light shell: install session failed for ${next.program.name}: " +
                    "${t.javaClass.simpleName}: ${t.message ?: "no message"}"
            )
            active = null
            installNext()
        }
    }

    /**
     * Called from [InstallResultReceiver] for every install the app starts
     * (shells and extensions both land here).
     */
    fun onResult(context: Context, packageName: String?, success: Boolean, message: String) {
        val ctx = context.applicationContext
        worker.execute {
            val current = active
            // Success callbacks normally name the installed package, but a
            // cancelled prompt reports none — fall back to the active session
            // so a shell never ends up installed without its VHD grant.
            val grantedPkg = packageName ?: current?.packageName
            if (success && grantedPkg != null) {
                // Grants are keyed per package, so an unrelated extension
                // install simply finds nothing to grant.
                LightShellPackager.grantVhdFor(ctx, grantedPkg)
            }
            // A cancelled prompt reports no package name, so treat that as the
            // active session's result too — otherwise the queue would stall.
            val matchesActive = current != null &&
                (packageName == null || packageName == current.packageName)
            if (matchesActive) {
                if (success) {
                    GuestLog.info("light shells: installed ${current.program.name}")
                    if (total == 1) {
                        main.post {
                            ShellEvents.pendingRun = ShellRunRequest(
                                current.packageName, current.program.name
                            )
                        }
                    }
                } else {
                    GuestLog.add(
                        "light shell: install failed for ${current.program.name}: " +
                            (message.ifBlank { "unknown reason" })
                    )
                }
                active = null
                installNext()
            } else if (!success) {
                GuestLog.add("install failed: ${packageName ?: "(unknown)"} $message")
            }
        }
    }
}
