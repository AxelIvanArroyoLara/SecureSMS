# SecureSMS hybrid v1 contract and experiment plan

This note fixes the wire contract Emilio's engines must keep and the measurements that will be reported. It is not a benchmark. The single RSA-2048 and P-256 timings already printed in the team guide are individual runs of different plaintexts. They are not averages and they are not reused here.

## Wire contract

The registered suite stays `HYBRID_V1` (wire id `01`). A new suite id would break Axel's application, so none is added.

| Profile | Wire id | Algorithm | App support |
| --- | --- | --- | --- |
| RSA-2048 | `01` | RSA | yes |
| RSA-3072 | `02` | RSA | yes |
| ECC P-256 | `03` | ECDH on secp256r1 | yes, Android 12+ for Keystore |
| ECC P-384 | `04` | ECDH on secp384r1 | yes, Android 12+ for Keystore |

Public keys leave the device as `SSK1.<wire id>.<unpadded Base64URL SPKI>`. The fingerprint is the hex SHA-256 of the SPKI bytes. A profile mismatch, such as a P-256 key imported as RSA-2048, is an invalid key.

Each operation returns elapsed time from a monotonic clock, in nanoseconds, and failures carry no key material.

Hybrid layout, identical for the reference engine and Emilio's engines:

- The authenticated header is 51 bytes: version `01`, suite, profile, message UUID, and the 32-byte recipient fingerprint.
- RSA metadata is a 12-byte nonce followed by an RSA-OAEP wrapping of a random 32-byte AES key. OAEP uses SHA-256, MGF1-SHA1, and an empty label, which is what Android Keystore accepts.
- ECC metadata is a 12-byte nonce followed by the ephemeral public key in DER SPKI on the recipient's curve. The AES key is HKDF-SHA256 over the ECDH secret, with the nonce as salt and the ASCII info `SecureSMS/v1/ECDH` plus the 51-byte header. One HMAC block produces 32 bytes.
- The message itself is AES-256-GCM with a 128-bit tag. The additional authenticated data is the header followed by the metadata.
- Plaintext `hello` is the bytes `68 65 6c 6c 6f`. A modified GCM tag fails with `INVALID_CIPHERTEXT`.

`EmilioRsaEngine` and `EmilioEccEngine` implement that layout with Java Cryptography Architecture primitives and the existing `IdentityVault`. `HybridCrypto` stays in the tree as the interoperability reference and is no longer the engine registered for carrier SMS. `DemoCrypto` stays registered for the offline simulator only.

## What is measured

Two blocks are stored separately. They are not averaged together.

**Hybrid block.** The four application profiles, through Emilio's engines. The same four plaintexts are used for every profile: empty, `hello` (5 bytes), 200 ASCII bytes, and 1024 ASCII bytes (the composer maximum). Each condition is repeated 30 times after a short warmup that is discarded. Recorded operations are key generation, hybrid encryption, and hybrid decryption. Encryption time includes AES-GCM and the asymmetric wrap or agreement. It does not include parsing the recipient SPKI. Envelope size and SMS segment count are recorded from the same ciphertext the timer measured. Segments use the application framer: `S1`, 128 Base64URL characters of payload per segment, at most 22 segments.

**Isolated block.** Asymmetric primitives only, with no AES-GCM and no SMS framing. Security-equivalent pairs, using NIST comparisons rather than the application's profile list:

| Pair | Why it is paired |
| --- | --- |
| RSA-2048 and P-224 (`secp224r1`) | about 112-bit security |
| RSA-3072 and P-256 | about 128-bit security |
| RSA-7680 and P-384 | about 192-bit security |

The application cannot send P-224 or RSA-7680. Those sizes stay in this block so the SMS wire format does not change.

RSA isolated encrypt and decrypt are OAEP wraps and unwraps of a 32-byte key, with the same OAEP parameters as the hybrid. ECC isolated encrypt and decrypt are one ECDH on each side, using keys generated outside the timed section. Key generation is its own operation. The platform SunEC build on the measurement JVM no longer implements `secp224r1`. The isolated block therefore uses BouncyCastle 1.78.1 for every primitive in that block, so the provider does not change between the two sides of a pair. The hybrid block does not use BouncyCastle. It uses the engines the application ships.

## Statistics and machine record

For every condition the raw file keeps each of the 30 samples. The summary reports the count, the median, the arithmetic mean, and the sample standard deviation (divisor `n - 1`). Times are nanoseconds in the CSV and milliseconds in the tables and charts. Each run records the operating system, JVM, CPU model, date, and whether the numbers came from in-memory JCA keys or from Android Keystore.

A JVM run is reproducible without a phone. It is not an Android Keystore measurement. Keystore and carrier delivery can move the hybrid times, so a device run has to be labeled as a device run. No two-phone campaign is claimed until those captures exist.
