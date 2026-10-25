package com.nine.shell

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * NINE's visual language for the light shell, in plain Views.
 *
 * The shell deliberately stays Compose-free (it is installed as a small
 * throw-away APK), but it must look like NINE: near-black background, cyan
 * accents, purple secondary action, letter-spaced monospace section labels and
 * rounded "card" panels with a hairline stroke.
 */
object ShellTheme {
    const val BG = 0xFF0A0A12.toInt()
    const val PANEL = 0xFF11111C.toInt()
    const val PANEL_STROKE = 0xFF1E2A3A.toInt()
    const val CYAN = 0xFF00E5FF.toInt()
    const val CYAN_SOFT = 0xFF80DEEA.toInt()
    const val PURPLE = 0xFF7C4DFF.toInt()
    const val TEXT = 0xFFFFFFFF.toInt()
    const val MUTED = 0xFF93A1AE.toInt()
    const val CYAN_WASH = 0x1F00E5FF

    fun px(ctx: Context, dp: Int): Int =
        (dp * ctx.resources.displayMetrics.density).toInt()

    fun fill(ctx: Context, color: Int, radiusDp: Int = 14, stroke: Int? = null): GradientDrawable =
        GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = px(ctx, radiusDp).toFloat()
            setColor(color)
            if (stroke != null) setStroke(px(ctx, 1).coerceAtLeast(1), stroke)
        }

    /** Letter-spaced uppercase micro-label, as used above the cards in NINE. */
    fun label(ctx: Context, text: String): TextView = TextView(ctx).apply {
        this.text = text
        setTextColor(CYAN)
        textSize = 10f
        letterSpacing = 0.18f
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
    }

    fun heading(ctx: Context, text: String, size: Float = 18f): TextView = TextView(ctx).apply {
        this.text = text
        setTextColor(TEXT)
        textSize = size
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }

    fun body(ctx: Context, text: String, color: Int = TEXT, size: Float = 13f): TextView =
        TextView(ctx).apply {
            this.text = text
            setTextColor(color)
            textSize = size
            setLineSpacing(px(ctx, 2).toFloat(), 1f)
        }

    fun card(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(px(ctx, 16), px(ctx, 14), px(ctx, 16), px(ctx, 16))
        background = fill(ctx, PANEL, 14, PANEL_STROKE)
    }

    /** "9" mark + program title + subtitle, matching NINE's header block. */
    fun header(ctx: Context, title: String, subtitle: String): LinearLayout {
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val mark = TextView(ctx).apply {
            text = "9"
            setTextColor(CYAN)
            textSize = 24f
            gravity = Gravity.CENTER
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            background = fill(ctx, CYAN_WASH, 12, CYAN)
        }
        row.addView(mark, LinearLayout.LayoutParams(px(ctx, 48), px(ctx, 48)))

        val col = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(ctx, 14), 0, 0, 0)
        }
        col.addView(heading(ctx, title, 18f))
        col.addView(TextView(ctx).apply {
            text = subtitle.uppercase()
            setTextColor(CYAN_SOFT)
            textSize = 9f
            letterSpacing = 0.22f
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        })
        row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        return row
    }

    fun primaryButton(ctx: Context, text: String, onClick: () -> Unit): Button =
        Button(ctx).apply {
            this.text = text
            isAllCaps = false
            textSize = 13f
            setTextColor(0xFF06121A.toInt())
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            background = fill(ctx, CYAN, 12)
            stateListAnimator = null
            minHeight = px(ctx, 44)
            setPadding(px(ctx, 18), px(ctx, 10), px(ctx, 18), px(ctx, 10))
            setOnClickListener { onClick() }
        }

    fun secondaryButton(ctx: Context, text: String, onClick: () -> Unit): Button =
        Button(ctx).apply {
            this.text = text
            isAllCaps = false
            textSize = 13f
            setTextColor(CYAN)
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            background = fill(ctx, PANEL, 12, CYAN)
            stateListAnimator = null
            minHeight = px(ctx, 44)
            setPadding(px(ctx, 18), px(ctx, 10), px(ctx, 18), px(ctx, 10))
            setOnClickListener { onClick() }
        }

    fun purpleButton(ctx: Context, text: String, onClick: () -> Unit): Button =
        Button(ctx).apply {
            this.text = text
            isAllCaps = false
            textSize = 13f
            setTextColor(TEXT)
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            background = fill(ctx, PURPLE, 12)
            stateListAnimator = null
            minHeight = px(ctx, 44)
            setPadding(px(ctx, 18), px(ctx, 10), px(ctx, 18), px(ctx, 10))
            setOnClickListener { onClick() }
        }

    /** Thin divider matching the panel stroke. */
    fun divider(ctx: Context): View = View(ctx).apply {
        setBackgroundColor(PANEL_STROKE)
    }.also {
        it.layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, px(ctx, 1).coerceAtLeast(1)
        )
    }

    fun switchTint(ctx: Context): ColorStateList =
        ColorStateList(
            arrayOf(
                intArrayOf(android.R.attr.state_checked),
                intArrayOf()
            ),
            intArrayOf(CYAN, 0xFF55616D.toInt())
        )

    fun trackTint(ctx: Context): ColorStateList =
        ColorStateList(
            arrayOf(
                intArrayOf(android.R.attr.state_checked),
                intArrayOf()
            ),
            intArrayOf(0x6600E5FF, 0x33FFFFFF)
        )
}
