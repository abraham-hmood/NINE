package com.nine.dbt

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlin.concurrent.thread

/**
 * adb-driven dev hook: run a guest ELF without touching the UI.
 *
 *   adb shell am broadcast -a com.nine.dbt.RUN_GUEST \
 *       -e path /data/data/com.nine.dbt/files/hello.elf
 *
 * Guarded by android.permission.DUMP so only shell/root can send it.
 * All native output flows through Logger -> GuestLog -> logcat (tag NINE*).
 */
class DevRunReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_RUN_GUEST) return
        val path = intent.getStringExtra(EXTRA_PATH) ?: run {
            GuestLog.add("devrun: no path extra")
            return
        }
        if (GuestRuntime.isRunning) {
            GuestLog.add("devrun: guest already running, ignoring $path")
            return
        }
        val cacheDir = context.cacheDir
        GuestLog.add("devrun: loading $path")
        thread(name = "devrun-guest") {
            try {
                val result = GuestRuntime.loadAndRunBlocking(path, cacheDir)
                GuestLog.add("devrun: RESULT $result")
            } catch (t: Throwable) {
                GuestLog.add("devrun: FAILED ${t.message}")
            }
        }
    }

    companion object {
        const val ACTION_RUN_GUEST = "com.nine.dbt.RUN_GUEST"
        const val EXTRA_PATH = "path"
    }
}
