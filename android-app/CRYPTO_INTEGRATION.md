# Crypto adapter integration

Implement `CryptoEngine` in the Android app. Each engine advertises one algorithm and suite and a set of profiles from RSA-2048, RSA-3072, P-256 and P-384. Register it inside the `CryptoRegistry` constructed by `SecureSmsApplication`. Replace the reference entry for its algorithm. A suite ID names a wire format, so coordinate and version any wire change on both endpoints before registering a different format.

`generate(profile, alias)` returns an opaque alias and DER SubjectPublicKeyInfo bytes. Keep the private key behind that alias. `validatePublicKey` validates the whole public key and the requested profile. A public key is exported as `SSK1.<profile wire ID>.<unpadded canonical Base64URL SPKI>`. Users compare the full hex SHA-256 SPKI fingerprint through a trusted channel before marking a contact key verified. For example, importing a P-256 share into an RSA-2048 association must return an invalid-key error.

`encrypt(context, spki, plaintext)` accepts UTF-8 bytes and returns metadata plus ciphertext. Only encrypt for the exact recipient fingerprint in the context. `decrypt(context, alias, payload)` authenticates the context and metadata before releasing plaintext, checks the local key fingerprint and returns typed failures. Measure real operations with a monotonic clock and return elapsed nanoseconds. Return no secrets in failures. For example, UTF-8 input `hello` must recover the bytes `68 65 6c 6c 6f` on the recipient and a modified GCM tag must fail with `INVALID_CIPHERTEXT`.

## Hybrid v1 format

- RSA metadata is a 12-byte random GCM nonce followed by a modulus-sized RSA-OAEP wrapped 32-byte random AES key. OAEP uses SHA-256, MGF1-SHA1 and the empty label for Android Keystore interoperability.
- ECC metadata is a 12-byte random GCM nonce followed by the ephemeral public key in DER SPKI on the recipient's curve. Compute ECDH and HKDF-SHA256 for 32 bytes using the nonce as salt and ASCII `SecureSMS/v1/ECDH` followed by the 51-byte context header as info.
- Use AES-256-GCM with a 128-bit tag appended to ciphertext. AAD is the 51-byte context header followed directly by metadata. For the 5-byte input above, the ciphertext and tag total 21 bytes.
- The demo suite reverses bytes and uses a public checksum. Keep it confined to the simulator.

Run `./gradlew testDebugUnitTest` for the JVM adapter contract. In `CryptoTest.hybridRoundTripChecksEveryProfileAndAuthenticatesContextAndMetadata`, substitute your adapter for `sender`, retaining the reference receiver. Repeat with your adapter as `receiver` and the reference sender. Run both directions for every supported profile, then confirm that modified UUID, fingerprint, metadata and tags are rejected. On Android repeat using independent app installations and exchange exported keys. The hybrid suite provides payload confidentiality and integrity. Sender authentication and contact-key distribution rely on the users' verification workflow and have separate threat boundaries.
