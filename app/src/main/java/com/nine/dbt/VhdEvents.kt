package com.nine.dbt

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * Messages produced outside any composable (Application VHD lifecycle hooks)
 * that the main screen surfaces as snackbars.
 */
object VhdEvents {
    var message by mutableStateOf<String?>(null)
}
