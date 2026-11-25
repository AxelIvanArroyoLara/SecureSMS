# RSA and ECC comparison on the Android receiver

These sections complement the desktop study in [RESULTS.md](RESULTS.md). The two runs are not pooled. Every figure below comes from one physical phone, recorded in [receiver-results/device-evidence.txt](receiver-results/device-evidence.txt). Raw samples are in [receiver-results/measurements.csv](receiver-results/measurements.csv). Aggregates are in [receiver-results/summary.csv](receiver-results/summary.csv).

## Methodology

The comparison required by the assignment was executed on the receiving side of SecureSMS. No carrier SMS was sent. The instrumented test `ReceiverBenchmarkTest` ran on a physical Motorola moto g32, not on an emulator. The device reported Android 15, API 35, build `lineage_devon-userdebug 15 BP1A.250505.005`. Its vendor fingerprint string still names the original Android 13 release; the running system is Android 15. The test refused to record results if the fingerprint, model, or hardware identified an emulator.

The engines were the ones registered in the application: `EmilioRsaEngine` for RSA-2048 and RSA-3072, and `EmilioEccEngine` for P-256 and P-384. Private keys were created in Android Keystore. The test checked that the private-key encoding exported by the Keystore was null, then deleted each alias. Encryption used the public key. Decryption used the Keystore private key. Before each timed decryption, the ciphertext was passed through the application's SMS segmenter and reassembler, which is the path the receiver uses after the segments arrive. The timer is the engine's monotonic clock and does not include that framing.

The same three plaintexts were used for every profile: 15 bytes of ASCII `A`, 200 bytes of ASCII `M`, and 1024 bytes of ASCII `X`. Each condition was repeated 30 times after two warmup calls that were discarded. Every decrypted buffer was compared with the original. All 360 round trips matched. The summary reports the median, the arithmetic mean, and the sample standard deviation with divisor `n - 1`.

## Results and Discussion

Encryption and decryption medians, means, and sample standard deviations, in milliseconds. Each cell is 30 repetitions.

| Profile | Bytes | Encrypt median | Encrypt mean | Encrypt SD | Decrypt median | Decrypt mean | Decrypt SD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RSA-2048 | 15 | 0.421 | 0.430 | 0.029 | 33.471 | 33.587 | 0.729 |
| RSA-2048 | 200 | 0.428 | 0.463 | 0.109 | 33.336 | 33.515 | 2.271 |
| RSA-2048 | 1024 | 0.442 | 0.448 | 0.023 | 33.246 | 32.776 | 1.229 |
| RSA-3072 | 15 | 0.545 | 0.575 | 0.123 | 73.633 | 74.494 | 4.259 |
| RSA-3072 | 200 | 0.535 | 0.541 | 0.021 | 73.312 | 74.945 | 5.319 |
| RSA-3072 | 1024 | 0.554 | 0.569 | 0.042 | 73.481 | 73.217 | 1.540 |
| ECC P-256 | 15 | 0.803 | 0.859 | 0.162 | 3.908 | 4.230 | 1.017 |
| ECC P-256 | 200 | 0.743 | 0.761 | 0.046 | 3.556 | 3.576 | 0.101 |
| ECC P-256 | 1024 | 0.784 | 0.792 | 0.046 | 4.006 | 4.515 | 1.283 |
| ECC P-384 | 15 | 3.532 | 3.685 | 0.484 | 7.536 | 8.245 | 1.190 |
| ECC P-384 | 200 | 3.569 | 3.657 | 0.426 | 7.460 | 7.930 | 0.933 |
| ECC P-384 | 1024 | 3.532 | 3.621 | 0.288 | 7.540 | 7.898 | 1.127 |

Charts: [receiver-results/receiver-encrypt.svg](receiver-results/receiver-encrypt.svg) and [receiver-results/receiver-decrypt.svg](receiver-results/receiver-decrypt.svg).

On this phone the receiver's private operation dominates. RSA-2048 decryption stays near 33 ms for every plaintext length, and RSA-3072 decryption stays near 73 ms. P-256 decryption is about 3.6 ms and P-384 decryption is about 7.5 ms. Message length from 15 to 1024 bytes does not move these times outside the sample scatter, because AES-GCM is small next to the Keystore operation.

RSA encryption remains the public operation and stays under 0.6 ms. ECC encryption includes an ephemeral key and ECDH, so P-256 encryption is about 0.7–0.8 ms and P-384 encryption is about 3.5 ms. For a 200-byte message, P-256 decryption is about nine times faster than RSA-2048 decryption and about twenty times faster than RSA-3072 decryption. Those profiles are not matched security levels. P-256 corresponds approximately to RSA-3072, which makes the receiver gap larger, not smaller.

The desktop study measured the same engines with in-memory keys. Its RSA-2048 decryption median for 200 bytes was about 1.0 ms. The same operation on this phone is about 33 ms. The difference is the Android Keystore private-key operation, which is what the receiving handset actually performs. The desktop numbers remain the controlled engine comparison. The phone numbers are the receiver comparison. They answer different questions and must stay in separate tables.

## Conclusions

All 360 decryptions on the moto g32 reproduced the original plaintext. At the receiver, with Android Keystore, ECC decryption is substantially faster than RSA decryption for every profile the application can send. RSA-3072 decryption costs about twice RSA-2048 decryption. Increasing the plaintext from 15 to 1024 bytes does not materially change either encryption or decryption time. The cost that does change with length is the number of SMS segments, already reported in the desktop study.

## Limitations

This is one physical phone, one Android 15 build, and 30 repetitions. It is not a carrier delivery measurement. The phone was unlocked and connected for the instrumented run. A second adb connection to the same handset crashed an earlier attempt; the numbers in this file come from the completed run of 360 verified round trips. The vendor fingerprint string still says Android 13 and must not be quoted as the version that executed the test.
