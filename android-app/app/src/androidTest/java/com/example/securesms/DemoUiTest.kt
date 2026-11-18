/** Recorre el envío, el cambio de usuario y los diagnósticos en Compose. */
package com.example.securesms

import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performSemanticsAction
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class DemoUiTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun sendReadAndInspectDemoMessage() {
        val sample = "Compose loopback ${UUID.randomUUID()}"
        compose.onNodeWithText("Open as Alice").performClick()
        compose.onNodeWithText("Message").performTextInput(sample)
        compose.onNodeWithText("Send").assertIsEnabled().performSemanticsAction(SemanticsActions.OnClick)
        compose.waitUntil(10_000) {
            compose.onAllNodesWithText("Demo  ·  Delivered", substring = true).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText("Open as Bob").performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithText(sample).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText(sample).assertIsDisplayed().performClick()
        compose.onNodeWithText("Message diagnostics").assertIsDisplayed()
        compose.onNodeWithText("Demo transform").assertIsDisplayed()
    }
}
