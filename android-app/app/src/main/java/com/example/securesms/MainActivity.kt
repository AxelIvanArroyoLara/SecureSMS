/** Punto de entrada Compose, permisos SMS y hoja de compartir de Android. */
package com.example.securesms

import android.Manifest
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableIntStateOf
import androidx.lifecycle.ViewModelProvider
import com.example.securesms.presentation.MessagingViewModel
import com.example.securesms.ui.SecureSmsScreen
import com.example.securesms.ui.theme.SecureSMSTheme

class MainActivity : ComponentActivity() {
    private val permissionRevision = mutableIntStateOf(0)
    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        permissionRevision.intValue++
    }

    override fun onResume() {
        super.onResume()
        permissionRevision.intValue++
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val model = ViewModelProvider(this)[MessagingViewModel::class.java]
        setContent {
            SecureSMSTheme {
                SecureSmsScreen(
                    model,
                    permissionRevision.intValue,
                    requestSms = { permissions.launch(arrayOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS)) },
                    share = { key ->
                        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, key)
                        }, "Share public key"))
                    }
                )
            }
        }
    }
}
