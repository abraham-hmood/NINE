package com.nine.dbt

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * App-wide wiring:
 *  - uncaught-exception capture → GuestLog (crashes land on the Logs tab)
 *  - VHD compression lifecycle: decompress when the first activity starts
 *    (foreground), re-compress when the last one stops (background), with
 *    snackbar messages published through [VhdEvents].
 */
class NineApplication : Application() {

    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var startedActivities = 0
    private var previousHandler: Thread.UncaughtExceptionHandler? = null

    override fun onCreate() {
        super.onCreate()

        previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            val msg = "FATAL uncaught on '${thread.name}': " +
                "${throwable.javaClass.name}: ${throwable.message}"
            runCatching { GuestLog.add(msg) }
            runCatching { Log.e("NINE", msg, throwable) }
            previousHandler?.uncaughtException(thread, throwable)
        }

        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityStarted(activity: Activity) {
                if (++startedActivities == 1) onEnteredForeground()
            }

            override fun onActivityStopped(activity: Activity) {
                if (--startedActivities == 0) onLeftForeground()
            }

            override fun onActivityCreated(a: Activity, b: Bundle?) {}
            override fun onActivityResumed(a: Activity) {}
            override fun onActivityPaused(a: Activity) {}
            override fun onActivitySaveInstanceState(a: Activity, b: Bundle) {}
            override fun onActivityDestroyed(a: Activity) {}
        })
    }

    private fun onEnteredForeground() {
        ioScope.launch {
            val msgs = runCatching { VhdManager.decompressAll(this@NineApplication) }
                .getOrElse {
                    GuestLog.add("vhd: foreground decompress failed: ${it.message}")
                    emptyList()
                }
            val notable = msgs.firstOrNull { "waste" in it || "already" in it || "failed" in it }
                ?: msgs.firstOrNull()
            if (notable != null) VhdEvents.message = notable
        }
    }

    private fun onLeftForeground() {
        ioScope.launch {
            runCatching { VhdManager.compressAll(this@NineApplication) }
                .onFailure { GuestLog.add("vhd: background compress failed: ${it.message}") }
        }
    }
}
