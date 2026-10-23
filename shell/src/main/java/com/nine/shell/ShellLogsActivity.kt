package com.nine.shell

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File

/**
 * Light-shell log viewer — shows the exact same stream as NINE's Logs tab:
 * every GuestLog line the shell's own com.nine.dbt.GuestLog recorded while
 * running the program (which also lands in logcat under the NINE tag).
 */
class ShellLogsActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            setBackgroundColor(Color.BLACK)
        }

        val title = TextView(this).apply {
            text = "PROGRAM LOGS"
            setTextColor(Color.CYAN)
            textSize = 20f
        }
        root.addView(title)

        var logText: TextView? = null

        val text = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            setTextColor(Color.rgb(0, 229, 255))
            textSize = 12f
            text = readLogText()
            logText = this
        }
        val scroll = ScrollView(this).apply { addView(text) }
        root.addView(scroll, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f).apply { topMargin = 24 })

        root.addView(Button(this).apply {
            setText("REFRESH")
            setOnClickListener { logText?.text = readLogText() }
        })
        root.addView(Button(this).apply {
            setText("BACK")
            setOnClickListener { finish() }
        })

        setContentView(root)
    }

    /** Same content as NINE's Logs tab: the session GuestLog stream. */
    private fun readLogText(): String {
        val f = File(File(filesDir, "guest-logs"), "session.log")
        if (!f.exists()) return "(no session log yet — press ⚙ back out and run the program)"
        return try {
            val lines = f.readLines()
            // tail like NINE's Logs tab (keeps the TextView responsive)
            if (lines.size > 500) "… ${lines.size - 500} earlier lines truncated …\n" +
                lines.takeLast(500).joinToString("\n")
            else lines.joinToString("\n")
        } catch (t: Throwable) {
            "(log read failed: ${t.message})"
        }
    }
}
