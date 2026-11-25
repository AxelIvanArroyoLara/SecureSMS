/** Benchmark de receptor en Android Keystore. No envía SMS. */
package com.example.securesms

import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.securesms.crypto.Algorithm
import com.example.securesms.crypto.AndroidIdentityVault
import com.example.securesms.crypto.CryptoContext
import com.example.securesms.crypto.CryptoEngine
import com.example.securesms.crypto.CryptoResult
import com.example.securesms.crypto.EmilioEccEngine
import com.example.securesms.crypto.EmilioRsaEngine
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.crypto.Suite
import com.example.securesms.crypto.fingerprint
import com.example.securesms.protocol.Envelope
import com.example.securesms.protocol.SmsProtocol
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ReceiverBenchmarkTest {
    @Test
    fun measuresEncryptAndDecryptOnThePhysicalReceiver() {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("receiverBenchmark") == "true")
        assertFalse(
            "Refusing to record emulator timings as a physical receiver. fingerprint=${Build.FINGERPRINT}",
            isEmulator()
        )
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = context.getExternalFilesDir(null) ?: context.filesDir
        val measurements = File(directory, "receiver-measurements.csv")
        val metadata = File(directory, "receiver-metadata.txt")
        val samples = StringBuilder()
        samples.appendLine(
            "block,profile,operation,plaintext_bytes,repetition,elapsed_ns,plaintext_matches," +
                "manufacturer,model,android_release,sdk_int"
        )
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val messages = listOf(
            ByteArray(15) { 'A'.code.toByte() },
            ByteArray(200) { 'M'.code.toByte() },
            ByteArray(1024) { 'X'.code.toByte() }
        )
        var checked = 0
        try {
            runBlocking {
                for (profile in KeyProfile.entries) {
                    if (Build.VERSION.SDK_INT < 31 && profile.algorithm == Algorithm.ECC) continue
                    Log.i(TAG, "receiver ${profile.label}")
                    val alias = "securesms.receiver.${profile.wire}.${UUID.randomUUID()}"
                    val engine = engineFor(profile)
                    try {
                        val identity = engine.generate(profile, alias).value()
                        assertNull(store.getKey(alias, null).encoded)
                        val cryptoContext = CryptoContext(
                            UUID.randomUUID(), Suite.HYBRID_V1, profile, fingerprint(identity.publicKey)
                        )
                        for (plaintext in messages) {
                            repeat(WARMUP) {
                                val cipher = engine.encrypt(cryptoContext, identity.publicKey, plaintext).value()
                                val opened = engine.decrypt(cryptoContext, alias, cipher).value()
                                assertArrayEquals(plaintext, opened)
                            }
                            repeat(REPETITIONS) { index ->
                                val encrypted = engine.encrypt(cryptoContext, identity.publicKey, plaintext).okResult()
                                val wire = SmsProtocol.reassemble(
                                    SmsProtocol.segment(Envelope(cryptoContext, encrypted.value)).map {
                                        SmsProtocol.parse(it)!!
                                    }
                                )!!
                                val decrypted = engine.decrypt(wire.context, alias, wire.payload).okResult()
                                assertArrayEquals(plaintext, decrypted.value)
                                checked += 1
                                samples.appendLine(row(profile, "encrypt", plaintext.size, index + 1, encrypted.elapsedNanos))
                                samples.appendLine(row(profile, "decrypt", plaintext.size, index + 1, decrypted.elapsedNanos))
                            }
                        }
                    } finally {
                        store.deleteEntry(alias)
                    }
                }
            }
        } finally {
            measurements.writeText(samples.toString())
            val record = deviceRecord(checked)
            metadata.writeText(record)
            logChunk("RECEIVER_META", record)
            logChunk("RECEIVER_CSV", samples.toString())
            Log.i(TAG, "wrote ${measurements.absolutePath} checked=$checked")
        }
        assertTrue(measurements.length() > 0)
        assertTrue("Expected ${KeyProfile.entries.size * messages.size * REPETITIONS} round trips, got $checked",
            checked == KeyProfile.entries.size * messages.size * REPETITIONS)
    }

    private fun row(profile: KeyProfile, operation: String, bytes: Int, repetition: Int, elapsed: Long): String =
        "receiver-keystore,${profile.label},$operation,$bytes,$repetition,$elapsed,true," +
            "${Build.MANUFACTURER},${Build.MODEL},${Build.VERSION.RELEASE},${Build.VERSION.SDK_INT}"

    private fun deviceRecord(checked: Int): String = """
        manufacturer=${Build.MANUFACTURER}
        model=${Build.MODEL}
        device=${Build.DEVICE}
        android_release=${Build.VERSION.RELEASE}
        sdk_int=${Build.VERSION.SDK_INT}
        build_display=${Build.DISPLAY}
        fingerprint=${Build.FINGERPRINT}
        hardware=${Build.HARDWARE}
        abi=${Build.SUPPORTED_ABIS.joinToString(" ")}
        emulator=${isEmulator()}
        repetitions=$REPETITIONS
        warmup_discarded=$WARMUP
        plaintext_15=15 bytes of ASCII A
        plaintext_200=200 bytes of ASCII M
        plaintext_1024=1024 bytes of ASCII X
        profiles=RSA-2048 RSA-3072 ECC P-256 ECC P-384
        engines=EmilioRsaEngine EmilioEccEngine
        key_storage=Android Keystore
        private_key_exported=false
        sms_sent=false
        measurement=engine monotonic nanoseconds for encrypt and for decrypt after SMS reassembly
        verified_round_trips=$checked
        dispersion=sample standard deviation computed later from the CSV
    """.trimIndent() + "\n"

    private fun logChunk(label: String, text: String) {
        val body = text.trimEnd()
        val size = 3000
        val parts = (body.length + size - 1) / size
        body.chunked(size).forEachIndexed { index, part ->
            Log.i(TAG, "$label ${index + 1}/$parts $part")
        }
    }

    private fun isEmulator(): Boolean {
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val hardware = Build.HARDWARE.lowercase()
        return fingerprint.contains("generic") || fingerprint.contains("emulator") ||
            model.contains("emulator") || model.contains("sdk_gphone") ||
            hardware.contains("goldfish") || hardware.contains("ranchu")
    }

    private fun engineFor(profile: KeyProfile): CryptoEngine = when (profile.algorithm) {
        Algorithm.RSA -> EmilioRsaEngine(AndroidIdentityVault(), setOf(profile))
        Algorithm.ECC -> EmilioEccEngine(AndroidIdentityVault(), setOf(profile))
    }

    private fun <T> CryptoResult<T>.value(): T = okResult().value

    private fun <T> CryptoResult<T>.okResult(): CryptoResult.Ok<T> {
        assertTrue(toString(), this is CryptoResult.Ok)
        return this as CryptoResult.Ok<T>
    }

    private companion object {
        const val TAG = "ReceiverBenchmark"
        const val REPETITIONS = 30
        const val WARMUP = 2
    }
}
