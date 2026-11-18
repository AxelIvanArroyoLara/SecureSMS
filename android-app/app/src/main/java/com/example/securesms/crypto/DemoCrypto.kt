/** Transformación determinista de prueba, exclusiva para la simulación sin red. */
package com.example.securesms.crypto

/** Los datos de demostración son reversibles públicamente y carecen de seguridad. */
class DemoCrypto(override val algorithm: Algorithm) : CryptoEngine {
    override val suite = Suite.MOCK
    override val profiles = KeyProfile.entries.filter { it.algorithm == algorithm }.toSet()

    private fun demoKey(profile: KeyProfile, alias: String) =
        "demo:${profile.wire}:$alias".encodeToByteArray()

    override suspend fun generate(profile: KeyProfile, alias: String) =
        timedCrypto(CryptoError.INVALID_KEY) {
            require(profile in profiles && alias in setOf("Alice", "Bob"))
            LocalIdentity(alias, demoKey(profile, alias))
        }

    override suspend fun validatePublicKey(profile: KeyProfile, spki: ByteArray) =
        timedCrypto(CryptoError.INVALID_KEY) {
            require(profile in profiles && listOf("Alice", "Bob").any { demoKey(profile, it).contentEquals(spki) })
        }

    override suspend fun encrypt(context: CryptoContext, spki: ByteArray, plaintext: ByteArray) =
        timedCrypto(CryptoError.INVALID_KEY) {
            require(context.suite == suite && context.profile in profiles)
            require(validatePublicKey(context.profile, spki) is CryptoResult.Ok)
            require(context.recipientFingerprint.contentEquals(fingerprint(spki)))
            CipherPayload(fingerprint(context.authenticatedHeader() + plaintext), plaintext.reversedArray())
        }

    override suspend fun decrypt(context: CryptoContext, alias: String, payload: CipherPayload) =
        timedCrypto(CryptoError.INVALID_CIPHERTEXT) {
            require(context.suite == suite && context.profile in profiles)
            require(context.recipientFingerprint.contentEquals(fingerprint(demoKey(context.profile, alias))))
            val plaintext = payload.ciphertext.reversedArray()
            require(payload.metadata.contentEquals(fingerprint(context.authenticatedHeader() + plaintext)))
            plaintext
        }
}
