# RSA and ECC component

These sections are ready to place in the project report. Every figure comes from the run recorded in [results/run-metadata.txt](results/run-metadata.txt). The raw samples are in [results/measurements.csv](results/measurements.csv) and the aggregates in [results/summary.csv](results/summary.csv).

## Methodology

SecureSMS does not encrypt an SMS with RSA or with a raw elliptic-curve operation. Each message is encrypted with AES-256-GCM. RSA-OAEP or ephemeral ECDH plus HKDF-SHA256 protects only the 32-byte AES key. The wire format is Hybrid v1, defined in [CONTRACT.md](CONTRACT.md): profiles RSA-2048, RSA-3072, P-256, and P-384. `EmilioRsaEngine` and `EmilioEccEngine` produce that format with Java Cryptography Architecture primitives. The earlier `HybridCrypto` class remains in the tree as the interoperability reference and is no longer the engine registered for carrier SMS.

Two experiments were run, and their results are not pooled.

The hybrid experiment calls the engines the application registers. Keys stay in memory. The same four plaintexts are used for every profile: an empty message, the five bytes of `hello`, 200 ASCII bytes, and 1024 ASCII bytes. Each condition is repeated 30 times after two warmup calls that are discarded. The recorded times are the engines' own monotonic measurements. Encryption time includes the AES-GCM step and the RSA wrap or the ephemeral ECDH. It does not include parsing the recipient public key. Decryption time includes authentication. Envelope size and SMS segment count come from the same ciphertext, using the application's `S1` framer.

The isolated experiment measures only the asymmetric primitive, with no AES-GCM and no SMS framing. The pairs follow approximate NIST security levels rather than the application's profile list, because the application has no P-224 or RSA-7680 profile and those sizes were not added to the SMS format.

| Pair | Approximate security | Algorithms |
| --- | --- | --- |
| RSA-2048 and P-224 | 112-bit | RSA-OAEP of 32 bytes, and one ECDH on secp224r1 |
| RSA-3072 and P-256 | 128-bit | RSA-OAEP of 32 bytes, and one ECDH on secp256r1 |
| RSA-7680 and P-384 | 192-bit | RSA-OAEP of 32 bytes, and one ECDH on secp384r1 |

For ECC, the encrypt sample is one ECDH from an ephemeral private key to the recipient public key, and the decrypt sample is one ECDH in the other direction. Those keys are generated outside the timed section. This platform's SunEC provider no longer implements secp224r1, so the whole isolated block uses BouncyCastle 1.78.1. The hybrid block does not.

The summary reports the median, the arithmetic mean, and the sample standard deviation with divisor `n - 1`. Tables below use milliseconds. The CSV keeps nanoseconds. RSA key generation has a heavy right tail, so the median is the central value used in the discussion.

The machine was an AMD Ryzen 7 5800H (16 threads) running Linux 7.0.0-42-generic. The Gradle toolchain ran Eclipse Adoptium 25.0.3. The run finished at 2026-11-19 22:27 (UTC-6). These are not Android Keystore timings and they are not timings from a phone.

## Results and Discussion

### Hybrid scheme used by the application

Key generation, 30 repetitions:

| Profile | Median (ms) | Mean (ms) | Sample SD (ms) |
| --- | ---: | ---: | ---: |
| RSA-2048 | 69.552 | 78.931 | 34.354 |
| RSA-3072 | 299.562 | 329.012 | 158.710 |
| ECC P-256 | 0.279 | 0.293 | 0.037 |
| ECC P-384 | 2.352 | 2.360 | 0.036 |

Encryption and decryption of the same 200-byte plaintext, with the resulting envelope:

| Profile | Encrypt median (ms) | Encrypt SD (ms) | Decrypt median (ms) | Decrypt SD (ms) | Envelope (bytes) | SMS segments |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RSA-2048 | 0.127 | 0.007 | 1.014 | 0.041 | 537 | 6 |
| RSA-3072 | 0.126 | 0.034 | 2.739 | 0.254 | 665 | 7 |
| ECC P-256 | 1.170 | 0.074 | 0.936 | 0.052 | 372 | 4 |
| ECC P-384 | 2.929 | 0.077 | 1.940 | 0.044 | 401 | 5 |

The 1024-byte plaintext, the largest message the composer accepts, changes the cryptographic time very little and changes the SMS cost a great deal:

| Profile | Encrypt median (ms) | Decrypt median (ms) | Envelope (bytes) | SMS segments |
| --- | ---: | ---: | ---: | ---: |
| RSA-2048 | 0.152 | 0.995 | 1361 | 15 |
| RSA-3072 | 0.125 | 2.724 | 1489 | 16 |
| ECC P-256 | 1.120 | 0.937 | 1196 | 13 |
| ECC P-384 | 2.946 | 1.944 | 1225 | 13 |

Charts for this block are [results/hybrid-keygen.svg](results/hybrid-keygen.svg), [results/hybrid-encrypt.svg](results/hybrid-encrypt.svg), [results/hybrid-decrypt.svg](results/hybrid-decrypt.svg), [results/hybrid-envelope.svg](results/hybrid-envelope.svg), and [results/hybrid-segments.svg](results/hybrid-segments.svg). Each series is one plaintext length.

RSA encryption is faster than ECC encryption in this hybrid. That follows from the operations inside the timer. RSA encryption is a public-exponent operation with exponent 65537, plus AES-GCM. ECC encryption generates a fresh ephemeral key and then runs ECDH. RSA decryption is the private operation, so it grows with the modulus: about 1.0 ms at 2048 bits and 2.7 ms at 3072 bits for the 200-byte message. P-256 decryption, about 0.94 ms, is close to RSA-2048 decryption on this JVM. Those two profiles are not a matched security pair. P-256 is the matched curve for RSA-3072, whose decryption median is 2.7 ms.

Plaintext length from 0 to 1024 bytes does not move the hybrid times outside the scatter already visible in the sample standard deviation. The asymmetric step dominates AES-GCM at these sizes. Length does move the SMS bill. An empty RSA-2048 message already needs 4 segments because the OAEP blob is 256 bytes. The same empty P-256 message needs 2 segments. At 1024 bytes the counts are 15 and 13.

The single device samples in the team guide (RSA-2048 encryption 2.523 ms and decryption 7.837 ms; P-256 encryption 7.177 ms and decryption 5.697 ms) are individual runs of different plaintexts. They are not means, and they are not mixed into the tables above. They were also taken through Android, where the private key can sit in the Keystore. The JVM figures here are a controlled comparison of the engines. A phone run would need its own label.

### Isolated primitives at matched sizes

Median of 30 repetitions. RSA rows time OAEP on a 32-byte key. ECC rows time one ECDH. Charts: [results/isolated-keygen.svg](results/isolated-keygen.svg) and [results/isolated-operations.svg](results/isolated-operations.svg). The vertical axis of both charts is logarithmic because RSA-7680 key generation is measured in seconds.

| Pair | Profile | Key generation (ms) | Public / ECDH side (ms) | Private / ECDH side (ms) |
| --- | --- | ---: | ---: | ---: |
| RSA-2048 and P-224 | RSA-2048 | 123.955 | 0.102 | 1.084 |
| RSA-2048 and P-224 | P-224 | 0.223 | 0.263 | 0.251 |
| RSA-3072 and P-256 | RSA-3072 | 535.525 | 0.122 | 2.879 |
| RSA-3072 and P-256 | P-256 | 0.216 | 0.280 | 0.278 |
| RSA-7680 and P-384 | RSA-7680 | 13294.547 | 0.437 | 35.421 |
| RSA-7680 and P-384 | P-384 | 0.617 | 0.804 | 0.818 |

At every matched pair, ECC key generation is far cheaper. The ratio of the medians is about 560 to 1 at the 112-bit pair, about 2,500 to 1 at the 128-bit pair, and about 22,000 to 1 at the 192-bit pair. RSA key generation is also the noisiest series in the study. For RSA-7680 the median is 13.3 s, the mean is 17.4 s, and the sample standard deviation is 14.6 s. Thirty repetitions are enough to show that this key generation takes seconds, and they are not enough to pin the mean to a tenth of a second. The median is the value that should be quoted.

The RSA private operation is slower than one ECDH at each pair: 1.084 ms against 0.251 ms, 2.879 ms against 0.278 ms, and 35.421 ms against 0.818 ms. The RSA public operation is faster than one ECDH at 2048 and 3072 bits. That split is why a hybrid RSA encryption, which uses the public key, can look faster than hybrid ECC encryption even when the matched private operation and the key generation favor ECC.

Bodur and Kara (2015) and Agoyi and Seral (2010) encrypt the SMS payload with the asymmetric algorithm. Their ciphertext size and their time then follow the number of RSA blocks and the modulus. Jintcharadze and Abashidze (2023) compare RSA and ECC as public-key schemes. Those timings describe a different construction from Hybrid v1. SecureSMS performs one asymmetric operation per message and uses AES-GCM for the body, so a longer SMS increases the segment count and does not add another RSA exponentiation. The isolated table is the part of this study that speaks to those papers. The hybrid table is the part that describes the application.

## Conclusions

The registered engines recover the original plaintext for every application profile, including the empty message and a 1024-byte message, and they accept ciphertext produced by the reference engine in both directions. A changed message id, metadata byte, or GCM tag is rejected, as is a P-256 key offered to an RSA-2048 slot.

On this JVM, hybrid encryption is under 0.2 ms for both RSA profiles and about 1.2 ms for P-256 and 2.9 ms for P-384, at a 200-byte plaintext. Hybrid decryption is about 1.0 ms for RSA-2048, 2.7 ms for RSA-3072, 0.94 ms for P-256, and 1.9 ms for P-384. ECC envelopes are smaller, so the same text costs fewer SMS segments.

At matched security sizes, ECC key generation and the private operation are much cheaper than RSA. RSA's public operation remains cheap. Quoting only the hybrid encryption column would hide that, because hybrid ECC encryption includes an ephemeral key generation that hybrid RSA encryption does not.

## Limitations

The sample is one laptop, 30 repetitions, and in-memory keys. Android Keystore and a carrier SMS were not part of this run. No handset was attached, so the instrumented tests were not repeated here, and a two-phone exchange is still pending. No defect report from the physical SMS trials was available to reproduce.

RSA key-generation means are pulled upward by slow outliers. Quote the median, and keep the standard deviation beside it.

The hybrid numbers and the isolated numbers use different providers. They answer different questions and must stay in separate tables. P-224 exists only in the isolated block. RSA-7680 is not a profile the application can send.
