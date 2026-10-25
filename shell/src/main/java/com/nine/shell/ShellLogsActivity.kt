package com.nine.shell

import android.app.Activity
import android.graphics.Typeface
import android.os.Bundle
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File

/**
 * Light-shell log viewer — the exact stream NINE's Logs tab shows: every
 * GuestLog line this shell recorded while running the program (which also
 * lands in logcat under the NINE tag), presented in NINE's monospace panel.
 */
class ShellLogsActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = ShellTheme.BG
        window.navigationBarColor = ShellTheme.BG

        val px = { dp: Int -> ShellTheme.px(this, dp) }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(20), px(24), px(20), px(24))
            setBackgroundColor(ShellTheme.BG)
        }

        root.addView(ShellTheme.header(this, "SESSION LOG", "NINE · LIGHT SHELL"))
        root.addView(android.view.View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, px(18)
            )
        })

        val card = ShellTheme.card(this)
        var logText: TextView? = null
        val text = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            setTextColor(ShellTheme.CYAN_SOFT)
            textSize = 11f
            text = readLogText()
            logText = this
        }
        val scroll = ScrollView(this).apply {
            addView(text, ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ))
        }
        card.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
        ))
        root.addView(card, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
        ))

        root.addView(android.view.View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, px(14)
            )
        })

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        actions.addView(ShellTheme.secondaryButton(this, "REFRESH") {
            logText?.text = readLogText()
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(android.view.View(this).apply {
            layoutParams = LinearLayout.LayoutParams(px(10), ViewGroup.LayoutParams.MATCH_PARENT)
        })
        actions.addView(ShellTheme.primaryButton(this, "BACK") { finish() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(actions)

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
