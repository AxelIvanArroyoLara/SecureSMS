/** Composición de dependencias y mantenimiento de estado a nivel de proceso. */
package com.example.securesms

import android.app.Application
import android.os.Build
import androidx.room.Room
import com.example.securesms.crypto.Algorithm
import com.example.securesms.crypto.AndroidIdentityVault
import com.example.securesms.crypto.CryptoRegistry
import com.example.securesms.crypto.DemoCrypto
import com.example.securesms.crypto.HistoryVault
import com.example.securesms.crypto.HybridCrypto
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.data.RoomStore
import com.example.securesms.data.SecureDatabase
import com.example.securesms.domain.Messaging
import com.example.securesms.protocol.Assembler
import com.example.securesms.transport.SmsTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class SecureSmsApplication : Application() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val sms by lazy { SmsTransport(this) }
    val store by lazy {
        RoomStore(Room.databaseBuilder(this, SecureDatabase::class.java, "securesms.db").build())
    }
    val messaging by lazy {
        val vault = AndroidIdentityVault()
        val registry = CryptoRegistry(
            DemoCrypto(Algorithm.RSA),
            DemoCrypto(Algorithm.ECC),
            HybridCrypto(Algorithm.RSA, vault, setOf(KeyProfile.RSA_2048, KeyProfile.RSA_3072)),
            HybridCrypto(Algorithm.ECC, vault, if (Build.VERSION.SDK_INT >= 31) {
                setOf(KeyProfile.P256, KeyProfile.P384)
            } else {
                emptySet()
            })
        )
        Messaging(store, registry, HistoryVault(), Assembler(store), sms)
    }

    override fun onCreate() {
        super.onCreate()
        scope.launch {
            while (isActive) {
                messaging.recover()
                val now = System.currentTimeMillis()
                store.expireSends(now - 5 * 60 * 1000L)
                delay(60_000)
            }
        }
    }
}
