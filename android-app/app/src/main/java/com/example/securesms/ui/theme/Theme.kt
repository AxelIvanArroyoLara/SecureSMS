/** Tema Material 3 con contraste y adaptación al modo del sistema. */
package com.example.securesms.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Light = lightColorScheme(
    primary = Color(0xFF006957),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFBCECDD),
    onPrimaryContainer = Color(0xFF07382E),
    secondary = Color(0xFF355E62),
    secondaryContainer = Color(0xFFD0EBED),
    onSecondaryContainer = Color(0xFF14383C),
    background = Color(0xFFF7FBFA),
    surface = Color(0xFFF7FBFA),
    onSurface = Color(0xFF162D30),
    surfaceVariant = Color(0xFFE5F0ED),
    onSurfaceVariant = Color(0xFF3F5857),
    outline = Color(0xFF65827D)
)

private val Dark = darkColorScheme(
    primary = Mint,
    onPrimary = Color(0xFF00382D),
    primaryContainer = Color(0xFF174F43),
    onPrimaryContainer = Color(0xFFC4F4E7),
    secondary = Color(0xFFA9D0D2),
    secondaryContainer = Color(0xFF25474B),
    onSecondaryContainer = Color(0xFFCEECEE),
    background = Color(0xFF101F21),
    surface = Color(0xFF101F21),
    onSurface = Color(0xFFE0EEEC),
    surfaceVariant = Color(0xFF233738),
    onSurfaceVariant = Color(0xFFBDCDCA),
    outline = Color(0xFF8BA5A0)
)

@Composable
fun SecureSMSTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (darkTheme) Dark else Light, typography = SecureTypography, content = content)
}
