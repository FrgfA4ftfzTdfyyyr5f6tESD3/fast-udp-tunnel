package com.example.ui.theme

import android.app.Activity
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat

private val MorphDarkColorScheme = darkColorScheme(
    primary = EmeraldCore,
    onPrimary = CyberBgPrimary,
    primaryContainer = ColorTokens.EmeraldContainer,
    onPrimaryContainer = EmeraldBright,
    secondary = BlueCore,
    onSecondary = TextPrimary,
    secondaryContainer = ColorTokens.BlueContainer,
    onSecondaryContainer = BlueBright,
    tertiary = PurpleCore,
    onTertiary = TextPrimary,
    tertiaryContainer = ColorTokens.PurpleContainer,
    onTertiaryContainer = PurpleBright,
    background = CyberBgPrimary,
    onBackground = TextPrimary,
    surface = CyberBgSurface,
    onSurface = TextPrimary,
    surfaceVariant = CyberBgSurfaceElevated,
    onSurfaceVariant = TextSecondary,
    outline = CyberBorderBright,
    outlineVariant = CyberGlassBorder,
    error = DangerCore,
    onError = TextPrimary,
    errorContainer = ColorTokens.DangerContainer,
    onErrorContainer = DangerBright,
)

private object ColorTokens {
    val EmeraldContainer = androidx.compose.ui.graphics.Color(0xFF0A2E23)
    val BlueContainer = androidx.compose.ui.graphics.Color(0xFF102446)
    val PurpleContainer = androidx.compose.ui.graphics.Color(0xFF231642)
    val DangerContainer = androidx.compose.ui.graphics.Color(0xFF3B1219)
}

val MorphShapes = Shapes(
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(22.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

@Composable
fun MorphCoreTheme(
    content: @Composable () -> Unit,
) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window
            if (window != null) {
                WindowCompat.getInsetsController(window, view).apply {
                    isAppearanceLightStatusBars = false
                    isAppearanceLightNavigationBars = false
                }
            }
        }
    }

    MaterialTheme(
        colorScheme = MorphDarkColorScheme,
        typography = Typography,
        shapes = MorphShapes,
        content = content
    )
}
