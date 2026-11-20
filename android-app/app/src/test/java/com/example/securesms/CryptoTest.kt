/** Pruebas de registro, compatibilidad de formatos e integridad criptográfica. */
package com.example.securesms

import com.example.securesms.crypto.*
import com.example.securesms.protocol.Envelope
import com.example.securesms.protocol.SmsProtocol
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

class CryptoTest {
    @Test
    fun registrySeparatesAlgorithmsAndSuites() {
        val rsa = DemoCrypto(Algorithm.RSA)
        val registry = CryptoRegistry(rsa)
        assertSame(rsa, registry.find(Suite.MOCK, KeyProfile.RSA_3072))
        assertNull(registry.find(Suite.MOCK, KeyProfile.P256))
        assertNull(registry.find(Suite.HYBRID_V1, KeyProfile.RSA_2048))
        assertThrows(IllegalArgumentException::class.java) { CryptoRegistry(rsa, rsa) }
    }

    @Test
    fun hybridRoundTripChecksEveryProfileAndAuthenticatesContextAndMetadata() = runBlocking {
        for (profile in KeyProfile.entries) {
            val vault = TestVault()
            val sender = HybridCrypto(profile.algorithm, TestVault(), setOf(profile))
            val receiver = HybridCrypto(profile.algorithm, vault, setOf(profile))
            val identity = receiver.generate(profile, "receiver").ok().value
            val context = CryptoContext(UUID.randomUUID(), Suite.HYBRID_V1, profile, fingerprint(identity.publicKey))
            val text = "hello 🌎".encodeToByteArray()
            val cipher = sender.encrypt(context, identity.publicKey, text).ok()
            assertTrue(cipher.elapsedNanos > 0)
            assertEquals(text.size + 16, cipher.value.ciphertext.size)
            val wire = SmsProtocol.segment(Envelope(context, cipher.value)).reversed()
            val incoming = SmsProtocol.reassemble(wire.map { SmsProtocol.parse(it)!! })!!
            val result = receiver.decrypt(incoming.context, identity.alias, incoming.payload).ok()
            assertArrayEquals(text, result.value)
            assertTrue(result.elapsedNanos > 0)
            assertEquals(CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT),
                receiver.decrypt(context.copy(id = UUID.randomUUID()), identity.alias, incoming.payload))
            assertEquals(CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT),
                receiver.decrypt(context, identity.alias, incoming.payload.copy(
                    metadata = incoming.payload.metadata.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() })))
            assertEquals(CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT),
                receiver.decrypt(context, identity.alias, incoming.payload.copy(
                    ciphertext = incoming.payload.ciphertext.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() })))
            assertEquals(CryptoResult.Failure(CryptoError.INVALID_KEY), sender.validatePublicKey(profile, byteArrayOf(0)))
            assertEquals(CryptoResult.Failure(CryptoError.INVALID_KEY),
                sender.encrypt(context.copy(recipientFingerprint = ByteArray(32)), identity.publicKey, text))
            assertEquals(CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT),
                receiver.decrypt(context, "missing", incoming.payload))
        }
    }

    @Test
    fun mockIsDeterministicAndRejectsWrongRecipient() = runBlocking {
        val engine = DemoCrypto(Algorithm.ECC)
        val profile = KeyProfile.P256
        val key = engine.generate(profile, "Bob").ok().value
        val context = CryptoContext(UUID.randomUUID(), Suite.MOCK, profile, fingerprint(key.publicKey))
        val input = "sample".encodeToByteArray()
        val first = engine.encrypt(context, key.publicKey, input).ok().value
        val second = engine.encrypt(context, key.publicKey, input).ok().value
        assertArrayEquals(first.ciphertext, second.ciphertext)
        assertArrayEquals(first.metadata, second.metadata)
        assertArrayEquals(input, engine.decrypt(context, "Bob", first).ok().value)
        assertEquals(CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT), engine.decrypt(context, "Alice", first))
    }

    @Test
    fun emilioInteroperatesWithReferenceInBothDirections() = runBlocking {
        val hello = "hello".encodeToByteArray()
        assertArrayEquals(byteArrayOf(0x68, 0x65, 0x6c, 0x6c, 0x6f), hello)
        val messages = listOf(ByteArray(0), hello, ByteArray(1024) { 'x'.code.toByte() })
        for (profile in KeyProfile.entries) {
            exchange(emilioEngine(profile, TestVault()), referenceEngine(profile, TestVault()), profile, messages)
            exchange(referenceEngine(profile, TestVault()), emilioEngine(profile, TestVault()), profile, messages)
        }
        val rsa = EmilioRsaEngine(TestVault(), setOf(KeyProfile.RSA_2048))
        val p256 = EmilioEccEngine(TestVault(), setOf(KeyProfile.P256))
            .generate(KeyProfile.P256, "peer").ok().value
        assertEquals(
            CryptoResult.Failure(CryptoError.INVALID_KEY),
            rsa.validatePublicKey(KeyProfile.RSA_2048, p256.publicKey)
        )
        assertEquals(
            CryptoResult.Failure(CryptoError.INVALID_KEY),
            rsa.validatePublicKey(KeyProfile.RSA_2048, byteArrayOf(0))
        )
    }

    private fun emilioEngine(profile: KeyProfile, vault: IdentityVault): CryptoEngine = when (profile.algorithm) {
        Algorithm.RSA -> EmilioRsaEngine(vault, setOf(profile))
        Algorithm.ECC -> EmilioEccEngine(vault, setOf(profile))
    }

    private fun referenceEngine(profile: KeyProfile, vault: IdentityVault): CryptoEngine =
        HybridCrypto(profile.algorithm, vault, setOf(profile))

    private suspend fun exchange(
        sender: CryptoEngine,
        receiver: CryptoEngine,
        profile: KeyProfile,
        messages: List<ByteArray>
    ) {
        val identity = receiver.generate(profile, "receiver").ok().value
        val context = CryptoContext(UUID.randomUUID(), Suite.HYBRID_V1, profile, fingerprint(identity.publicKey))
        for (text in messages) {
            val cipher = sender.encrypt(context, identity.publicKey, text).ok()
            assertTrue(cipher.elapsedNanos > 0)
            val wire = SmsProtocol.segment(Envelope(context, cipher.value))
            val incoming = SmsProtocol.reassemble(wire.map { SmsProtocol.parse(it)!! })!!
            val opened = receiver.decrypt(incoming.context, identity.alias, incoming.payload).ok()
            assertArrayEquals(text, opened.value)
            assertTrue(opened.elapsedNanos > 0)
            if (text.size != 5) continue
            assertEquals(
                CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT),
                receiver.decrypt(context.copy(id = UUID.randomUUID()), identity.alias, incoming.payload)
            )
            assertEquals(
                CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT),
                receiver.decrypt(context, identity.alias, incoming.payload.copy(
                    metadata = incoming.payload.metadata.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
                ))
            )
            assertEquals(
                CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT),
                receiver.decrypt(context, identity.alias, incoming.payload.copy(
                    ciphertext = incoming.payload.ciphertext.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
                ))
            )
            assertEquals(
                CryptoResult.Failure(CryptoError.INVALID_KEY),
                sender.encrypt(context.copy(recipientFingerprint = ByteArray(32)), identity.publicKey, text)
            )
            assertEquals(
                CryptoResult.Failure(CryptoError.INVALID_CIPHERTEXT),
                receiver.decrypt(context, "missing", incoming.payload)
            )
        }
    }

    private fun <T> CryptoResult<T>.ok(): CryptoResult.Ok<T> {
        assertTrue(toString(), this is CryptoResult.Ok)
        return this as CryptoResult.Ok<T>
    }
}

internal class TestVault : IdentityVault {
    private val keys = mutableMapOf<String, KeyPair>()

    override fun create(profile: KeyProfile, alias: String): PublicKey {
        val pair = when (profile.algorithm) {
            Algorithm.RSA -> KeyPairGenerator.getInstance("RSA").run {
                initialize(if (profile == KeyProfile.RSA_2048) 2048 else 3072)
                generateKeyPair()
            }
            Algorithm.ECC -> KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec(if (profile == KeyProfile.P256) "secp256r1" else "secp384r1"))
                generateKeyPair()
            }
        }
        keys[alias] = pair
        return pair.public
    }

    override fun load(alias: String): KeyPair = keys[alias] ?: throw java.security.InvalidKeyException()
}
