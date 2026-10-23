package com.nine.dbt

import android.util.Log

/** Light-shell copy of NINE's AppLog — same TAG so logcat filters match. */
object AppLog {
    private const val TAG = "NINE"

    fun d(where: String, msg: String) = Log.d(TAG, "[$where] $msg")
    fun i(where: String, msg: String) = Log.i(TAG, "[$where] $msg")
    fun w(where: String, msg: String) = Log.w(TAG, "[$where] $msg")
    fun e(where: String, msg: String, t: Throwable? = null) {
        if (t != null) Log.e(TAG, "[$where] $msg", t) else Log.e(TAG, "[$where] $msg")
    }
}
