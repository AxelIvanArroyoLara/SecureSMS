/** Adaptadores de Android Keystore para identidades y cuerpos del historial. */
package com.example.securesms.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private fun androidKeyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

class AndroidIdentityVault : IdentityVault {
    override fun create(profile: KeyProfile, alias: String): PublicKey {
        val generator = when (profile.algorithm) {
            Algorithm.RSA -> KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").apply {
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(profile.bits)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                if (Build.VERSION.SDK_INT >= 35) spec.setMgf1Digests(KeyProperties.DIGEST_SHA1)
                initialize(spec.build())
            }
            Algorithm.ECC -> {
                require(Build.VERSION.SDK_INT >= 31)
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                    initialize(
                        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                            .setAlgorithmParameterSpec(ECGenParameterSpec(profile.curve)).build()
                    )
                }
            }
        }
        return generator.generateKeyPair().public
    }

    override fun load(alias: String): KeyPair {
        val store = androidKeyStore()
        val key = store.getKey(alias, null) as? java.security.PrivateKey
            ?: throw java.security.InvalidKeyException()
        val cert = store.getCertificate(alias) ?: throw java.security.InvalidKeyException()
        return KeyPair(cert.publicKey, key)
    }
}

/** Sella el texto local y vincula el registro como datos asociados. */
class HistoryVault {
    @Synchronized
    private fun key(): SecretKey {
        val alias = "securesms.history.v1"
        val current = androidKeyStore().getKey(alias, null) as? SecretKey
        return current ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build()
            )
            generateKey()
        }
    }

    fun seal(id: String, plaintext: ByteArray): ByteArray? =
        (timedCrypto(CryptoError.OPERATION_FAILED) {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(id.encodeToByteArray())
            cipher.iv + cipher.doFinal(plaintext)
        } as? CryptoResult.Ok)?.value

    fun open(id: String, sealed: ByteArray): String? =
        (timedCrypto(CryptoError.OPERATION_FAILED) {
            require(sealed.size >= 28)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, 12))
            cipher.updateAAD(id.encodeToByteArray())
            cipher.doFinal(sealed, 12, sealed.size - 12).decodeToString()
        } as? CryptoResult.Ok)?.value
}
