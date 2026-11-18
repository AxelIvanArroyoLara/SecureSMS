/** Contrato de claves, suites y operaciones criptográficas de SecureSMS. */
package com.example.securesms.crypto

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

enum class Algorithm { RSA, ECC }

enum class KeyProfile(val wire: Int, val algorithm: Algorithm, val label: String) {
    RSA_2048(1, Algorithm.RSA, "RSA-2048"),
    RSA_3072(2, Algorithm.RSA, "RSA-3072"),
    P256(3, Algorithm.ECC, "ECC P-256"),
    P384(4, Algorithm.ECC, "ECC P-384")
}

/** Identifica un formato interoperable de metadatos y cifrado. */
enum class Suite(val wire: Int, val smsCapable: Boolean) {
    MOCK(0, false), HYBRID_V1(1, true)
}

enum class CryptoError(val description: String) {
    UNAVAILABLE("Crypto engine unavailable"),
    INVALID_KEY("Invalid key or key profile"),
    INVALID_CIPHERTEXT("Ciphertext authentication failed"),
    OPERATION_FAILED("Cryptographic operation failed")
}

sealed interface CryptoResult<out T> {
    data class Ok<T>(val value: T, val elapsedNanos: Long) : CryptoResult<T>
    data class Failure(val error: CryptoError) : CryptoResult<Nothing>
}

/** Clave pública SPKI y referencia opaca a la clave privada local. */
data class LocalIdentity(val alias: String, val publicKey: ByteArray)
data class CipherPayload(val metadata: ByteArray, val ciphertext: ByteArray)

/** Contexto que debe autenticarse en cada operación de cifrado y descifrado. */
data class CryptoContext(
    val id: UUID,
    val suite: Suite,
    val profile: KeyProfile,
    val recipientFingerprint: ByteArray
) {
    fun authenticatedHeader(): ByteArray = ByteBuffer.allocate(51)
        .put(1)
        .put(suite.wire.toByte())
        .put(profile.wire.toByte())
        .putLong(id.mostSignificantBits)
        .putLong(id.leastSignificantBits)
        .put(recipientFingerprint)
        .array()
}

/** La implementación protege claves privadas y define un formato según su suite. */
interface CryptoEngine {
    val algorithm: Algorithm
    val suite: Suite
    val profiles: Set<KeyProfile>

    suspend fun generate(profile: KeyProfile, alias: String): CryptoResult<LocalIdentity>
    suspend fun validatePublicKey(profile: KeyProfile, spki: ByteArray): CryptoResult<Unit>
    suspend fun encrypt(context: CryptoContext, spki: ByteArray, plaintext: ByteArray): CryptoResult<CipherPayload>
    suspend fun decrypt(context: CryptoContext, alias: String, payload: CipherPayload): CryptoResult<ByteArray>
}

/** Registra un solo motor por par de suite y algoritmo. */
class CryptoRegistry(vararg engines: CryptoEngine) {
    private val entries = engines.associateBy { it.suite to it.algorithm }

    init {
        require(entries.size == engines.size)
        require(engines.all { engine -> engine.profiles.all { it.algorithm == engine.algorithm } })
    }

    fun find(suite: Suite, profile: KeyProfile): CryptoEngine? =
        entries[suite to profile.algorithm]?.takeIf { profile in it.profiles }
}

fun fingerprint(spki: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(spki)
fun fingerprintText(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

internal inline fun <T> timedCrypto(error: CryptoError, operation: () -> T): CryptoResult<T> {
    val start = System.nanoTime()
    return try {
        CryptoResult.Ok(operation(), System.nanoTime() - start)
    } catch (_: java.security.GeneralSecurityException) {
        CryptoResult.Failure(error)
    } catch (_: IllegalArgumentException) {
        CryptoResult.Failure(error)
    } catch (_: java.security.ProviderException) {
        CryptoResult.Failure(error)
    }
}
