/** Motores híbridos de Emilio. El formato es el de Hybrid v1; la referencia no se modifica. */
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

private val hybridOaep = OAEPParameterSpec(
    "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT
)

/** RSA-OAEP envuelve la clave AES. La curva del destinatario no participa. */
class EmilioRsaEngine(
    private val vault: IdentityVault,
    override val profiles: Set<KeyProfile>
) : CryptoEngine {
    override val algorithm = Algorithm.RSA
    override val suite = Suite.HYBRID_V1
    private val random = SecureRandom()

    init {
        require(profiles.all { it.algorithm == Algorithm.RSA })
    }

    override suspend fun generate(profile: KeyProfile, alias: String) =
        timedCrypto(CryptoError.OPERATION_FAILED) {
            require(profile in profiles)
            LocalIdentity(alias, vault.create(profile, alias).encoded)
        }

    override suspend fun validatePublicKey(profile: KeyProfile, spki: ByteArray) =
        timedCrypto(CryptoError.INVALID_KEY) {
            rsaPublicKey(profile, spki)
            Unit
        }

    override suspend fun encrypt(
        context: CryptoContext,
        spki: ByteArray,
        plaintext: ByteArray
    ): CryptoResult<CipherPayload> {
        val recipient = when (val parsed = timedCrypto(CryptoError.INVALID_KEY) {
            require(context.suite == suite && context.profile in profiles)
            require(fingerprint(spki).contentEquals(context.recipientFingerprint))
            rsaPublicKey(context.profile, spki)
        }) {
            is CryptoResult.Failure -> return parsed
            is CryptoResult.Ok -> parsed.value
        }
        return timedCrypto(CryptoError.OPERATION_FAILED) {
            val nonce = ByteArray(12).also(random::nextBytes)
            val aesKey = ByteArray(32).also(random::nextBytes)
            try {
                val header = context.authenticatedHeader()
                val wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding")
                wrapper.init(Cipher.ENCRYPT_MODE, recipient, hybridOaep)
                val metadata = nonce + wrapper.doFinal(aesKey)
                CipherPayload(metadata, hybridGcm(Cipher.ENCRYPT_MODE, aesKey, nonce, header + metadata, plaintext))
            } finally {
                aesKey.fill(0)
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
            val wrapped = payload.metadata.copyOfRange(12, payload.metadata.size)
            require(wrapped.size == context.profile.bits / 8)
            val wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding")
            wrapper.init(Cipher.DECRYPT_MODE, local.private, hybridOaep)
            val aesKey = wrapper.doFinal(wrapped)
            try {
                require(aesKey.size == 32)
                val header = context.authenticatedHeader()
                hybridGcm(Cipher.DECRYPT_MODE, aesKey, nonce, header + payload.metadata, payload.ciphertext)
            } finally {
                aesKey.fill(0)
            }
        }
}

/** ECDH efímero y HKDF. No cifra el SMS con la curva. */
class EmilioEccEngine(
    private val vault: IdentityVault,
    override val profiles: Set<KeyProfile>
) : CryptoEngine {
    override val algorithm = Algorithm.ECC
    override val suite = Suite.HYBRID_V1
    private val random = SecureRandom()

    init {
        require(profiles.all { it.algorithm == Algorithm.ECC })
    }

    override suspend fun generate(profile: KeyProfile, alias: String) =
        timedCrypto(CryptoError.OPERATION_FAILED) {
            require(profile in profiles)
            LocalIdentity(alias, vault.create(profile, alias).encoded)
        }

    override suspend fun validatePublicKey(profile: KeyProfile, spki: ByteArray) =
        timedCrypto(CryptoError.INVALID_KEY) {
            ecPublicKey(profile, spki)
            Unit
        }

    override suspend fun encrypt(
        context: CryptoContext,
        spki: ByteArray,
        plaintext: ByteArray
    ): CryptoResult<CipherPayload> {
        val recipient = when (val parsed = timedCrypto(CryptoError.INVALID_KEY) {
            require(context.suite == suite && context.profile in profiles)
            require(fingerprint(spki).contentEquals(context.recipientFingerprint))
            ecPublicKey(context.profile, spki)
        }) {
            is CryptoResult.Failure -> return parsed
            is CryptoResult.Ok -> parsed.value
        }
        return timedCrypto(CryptoError.OPERATION_FAILED) {
            val nonce = ByteArray(12).also(random::nextBytes)
            val header = context.authenticatedHeader()
            val ephemeral = ephemeralPair(context.profile)
            val agreement = KeyAgreement.getInstance("ECDH")
            agreement.init(ephemeral.private)
            agreement.doPhase(recipient, true)
            val aesKey = hybridHkdf(agreement.generateSecret(), nonce, header)
            val metadata = nonce + ephemeral.public.encoded
            try {
                CipherPayload(metadata, hybridGcm(Cipher.ENCRYPT_MODE, aesKey, nonce, header + metadata, plaintext))
            } finally {
                aesKey.fill(0)
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
            val ephemeral = payload.metadata.copyOfRange(12, payload.metadata.size)
            val header = context.authenticatedHeader()
            val agreement = KeyAgreement.getInstance("ECDH")
            agreement.init(local.private)
            agreement.doPhase(ecPublicKey(context.profile, ephemeral), true)
            val aesKey = hybridHkdf(agreement.generateSecret(), nonce, header)
            try {
                require(aesKey.size == 32)
                hybridGcm(Cipher.DECRYPT_MODE, aesKey, nonce, header + payload.metadata, payload.ciphertext)
            } finally {
                aesKey.fill(0)
            }
        }
}

private fun rsaPublicKey(profile: KeyProfile, spki: ByteArray): PublicKey {
    require(profile.algorithm == Algorithm.RSA && spki.size in 1..768)
    val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spki)) as RSAPublicKey
    require(
        key.modulus.bitLength() == profile.bits &&
            key.publicExponent.toInt() == 65537 &&
            key.publicExponent.bitLength() == 17
    )
    return key
}

private fun ecPublicKey(profile: KeyProfile, spki: ByteArray): PublicKey {
    require(profile.algorithm == Algorithm.ECC && spki.size in 1..768)
    val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki)) as ECPublicKey
    val parameters = java.security.AlgorithmParameters.getInstance("EC")
    parameters.init(ECGenParameterSpec(profile.curve))
    val expected = parameters.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
    require(
        key.params.curve == expected.curve &&
            key.params.generator == expected.generator &&
            key.params.order == expected.order &&
            key.params.cofactor == expected.cofactor
    )
    return key
}

private fun ephemeralPair(profile: KeyProfile): KeyPair =
    KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec(profile.curve))
        generateKeyPair()
    }

private fun hybridGcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray =
    Cipher.getInstance("AES/GCM/NoPadding").run {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        updateAAD(aad)
        doFinal(input)
    }

/** RFC 5869 con una sola expansión. Borra el secreto ECDH antes de devolver la clave AES. */
private fun hybridHkdf(secret: ByteArray, salt: ByteArray, header: ByteArray): ByteArray {
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
