package com.nine.dbt

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarData
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import kotlin.math.abs
import kotlinx.coroutines.launch

/**
 * [SnackbarHost] whose messages can be dragged away in either direction.
 *
 * Every snackbar NINE shows is informational (VHD lifecycle events, export and
 * delete results, launch failures), so a swipe should dismiss it instead of
 * forcing the user to wait out the timeout. Dragging up or down moves the card
 * with the finger, fades it slightly, and either springs back or — past
 * [DISMISS_THRESHOLD] — flies off in the drag direction and dismisses the
 * message. Taps on an action button are unaffected: the gesture detector only
 * takes over past the touch slop.
 */
@Composable
fun DismissibleSnackbarHost(
    hostState: SnackbarHostState,
    modifier: Modifier = Modifier,
) {
    SnackbarHost(hostState = hostState, modifier = modifier) { data ->
        DismissibleSnackbar(data)
    }
}

private val DISMISS_THRESHOLD = 48.dp

@Composable
private fun DismissibleSnackbar(data: SnackbarData) {
    val density = LocalDensity.current
    val offset = remember { Animatable(0f) }
    val scope = rememberCoroutineScope()
    val thresholdPx = with(density) { DISMISS_THRESHOLD.toPx() }
    val fadeOver = thresholdPx * 4f

    Box(
        modifier = Modifier
            .graphicsLayer {
                translationY = offset.value
                // Fade as the card travels, but never fully away mid-drag.
                alpha = (1f - abs(offset.value) / fadeOver).coerceIn(0.35f, 1f)
            }
            .pointerInput(data) {
                detectVerticalDragGestures(
                    onVerticalDrag = { change, dragAmount ->
                        change.consume()
                        scope.launch { offset.snapTo(offset.value + dragAmount) }
                    },
                    onDragEnd = {
                        if (abs(offset.value) >= thresholdPx) {
                            val target = if (offset.value < 0f) -size.height * 2f
                                         else size.height * 2f
                            scope.launch {
                                offset.animateTo(target, animationSpec = tween(150))
                                data.dismiss()
                            }
                        } else {
                            scope.launch {
                                offset.animateTo(0f, spring(stiffness = Spring.StiffnessMediumLow))
                            }
                        }
                    },
                    onDragCancel = {
                        scope.launch {
                            offset.animateTo(0f, spring(stiffness = Spring.StiffnessMediumLow))
                        }
                    }
                )
            }
    ) {
        Snackbar(snackbarData = data)
    }
}
