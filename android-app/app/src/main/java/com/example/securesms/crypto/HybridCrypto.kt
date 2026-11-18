/** Adaptador híbrido de referencia basado en JCA y claves privadas protegidas. */
package com.example.securesms.crypto

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/** El proveedor de producción conserva las claves privadas dentro de Android Keystore. */
interface IdentityVault {
    fun create(profile: KeyProfile, alias: String): PublicKey
    fun load(alias: String): KeyPair
}

internal val KeyProfile.curve: String get() = if (this == KeyProfile.P256) "secp256r1" else "secp384r1"
internal val KeyProfile.bits: Int get() = when (this) {
    KeyProfile.RSA_2048 -> 2048
    KeyProfile.RSA_3072 -> 3072
    KeyProfile.P256 -> 256
    KeyProfile.P384 -> 384
}

/** RSA envuelve una clave aleatoria. ECC deriva la clave mediante ECDH efímero y HKDF. */
class HybridCrypto(
    override val algorithm: Algorithm,
    private val vault: IdentityVault,
    override val profiles: Set<KeyProfile>
) : CryptoEngine {
    override val suite = Suite.HYBRID_V1
    private val random = SecureRandom()
    private val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    override suspend fun generate(profile: KeyProfile, alias: String) =
        timedCrypto(CryptoError.OPERATION_FAILED) {
            require(profile in profiles)
            LocalIdentity(alias, vault.create(profile, alias).encoded)
        }

    override suspend fun validatePublicKey(profile: KeyProfile, spki: ByteArray) =
        timedCrypto(CryptoError.INVALID_KEY) {
            publicKey(profile, spki)
            Unit
        }

    override suspend fun encrypt(context: CryptoContext, spki: ByteArray, plaintext: ByteArray): CryptoResult<CipherPayload> {
        val recipient = when (val result = timedCrypto(CryptoError.INVALID_KEY) {
            require(context.suite == suite && fingerprint(spki).contentEquals(context.recipientFingerprint))
            publicKey(context.profile, spki)
        }) {
            is CryptoResult.Failure -> return result
            is CryptoResult.Ok -> result.value
        }
        return timedCrypto(CryptoError.OPERATION_FAILED) {
            val nonce = ByteArray(12).also(random::nextBytes)
            val header = context.authenticatedHeader()
            val (secret, material) = when (algorithm) {
                Algorithm.RSA -> {
                    val key = ByteArray(32).also(random::nextBytes)
                    val wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding")
                    wrapper.init(Cipher.ENCRYPT_MODE, recipient, oaep)
                    key to wrapper.doFinal(key)
                }
                Algorithm.ECC -> {
                    val ephemeral = generateEc(context.profile)
                    val agreement = KeyAgreement.getInstance("ECDH")
                    agreement.init(ephemeral.private)
                    agreement.doPhase(recipient, true)
                    hkdf(agreement.generateSecret(), nonce, header) to ephemeral.public.encoded
                }
            }
            val metadata = nonce + material
            try {
                CipherPayload(metadata, gcm(Cipher.ENCRYPT_MODE, secret, nonce, header + metadata, plaintext))
            } finally {
                secret.fill(0)
            }
        }
    }

    override suspend fun decrypt(context: CryptoContext, alias: String, payload: CipherPayload) =
        timedCrypto(CryptoError.INVALID_CIPHERTEXT) {
            require(context.suite == suite && context.profile in profiles)
            require(payload.metadata.size in 13..768 && payload.ciphertext.size >= 16)
            val local = vault.load(alias)
            require(fingerprint(local.public.encoded).contentEquals(context.recipientFingerprint))
            val nonce = payload.metadata.copyOfRange(0, 12)
            val material = payload.metadata.copyOfRange(12, payload.metadata.size)
            val header = context.authenticatedHeader()
            val key = when (algorithm) {
                Algorithm.RSA -> {
                    require(material.size == context.profile.bits / 8)
                    val wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding")
                    wrapper.init(Cipher.DECRYPT_MODE, local.private, oaep)
                    wrapper.doFinal(material)
                }
                Algorithm.ECC -> {
                    val agreement = KeyAgreement.getInstance("ECDH")
                    agreement.init(local.private)
                    agreement.doPhase(publicKey(context.profile, material), true)
                    hkdf(agreement.generateSecret(), nonce, header)
                }
            }
            try {
                require(key.size == 32)
                gcm(Cipher.DECRYPT_MODE, key, nonce, header + payload.metadata, payload.ciphertext)
            } finally {
                key.fill(0)
            }
        }

    private fun publicKey(profile: KeyProfile, spki: ByteArray): PublicKey {
        require(profile in profiles && spki.size in 1..768)
        return when (algorithm) {
            Algorithm.RSA -> {
                val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spki)) as RSAPublicKey
                require(key.modulus.bitLength() == profile.bits && key.publicExponent.toInt() == 65537 &&
                    key.publicExponent.bitLength() == 17)
                key
            }
            Algorithm.ECC -> {
                val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki)) as ECPublicKey
                val parameters = java.security.AlgorithmParameters.getInstance("EC")
                parameters.init(ECGenParameterSpec(profile.curve))
                val expected = parameters.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
                require(key.params.curve == expected.curve && key.params.generator == expected.generator &&
                    key.params.order == expected.order && key.params.cofactor == expected.cofactor)
                key
            }
        }
    }

    private fun generateEc(profile: KeyProfile): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec(profile.curve))
        generateKeyPair()
    }

    private fun gcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
            doFinal(input)
        }

    // RFC 5869 con una sola ronda de expansión para una clave AES de 32 bytes.
    private fun hkdf(secret: ByteArray, salt: ByteArray, header: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, mac.algorithm))
        val prk = try {
            mac.doFinal(secret)
        } finally {
            secret.fill(0)
        }
        return try {
            mac.init(SecretKeySpec(prk, mac.algorithm))
            mac.doFinal("SecureSMS/v1/ECDH".encodeToByteArray() + header + 1.toByte())
        } finally {
            prk.fill(0)
        }
    }
}
