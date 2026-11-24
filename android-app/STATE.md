# Android application state

The Android Gradle project and application sources are contained in `android-app/`. RSA/ECC measurements live in `crypto-benchmark/`. Wireshark and blockchain research stay independent.

## Implemented

- Compose inbox and chat, two-user offline demo, encryption configuration, key management and diagnostics.
- Room conversations, messages, contacts, identities, per-segment receipts and bounded pending fragments. Keystore seals message bodies. Interrupted complete batches can resume from Room.
- Android SMS send, receive and status callbacks gated by permissions, SIM selection, a carrier-capable crypto suite and a verified recipient key.
- Crypto engine contract, a reference Hybrid v1 adapter, and the registered `EmilioRsaEngine` and `EmilioEccEngine` adapters. The deterministic demo transform is confined to its own transport and suite.

## Verified

The debug APK builds. On the original Apple Silicon run it cold-launched on the API 37 emulator, with ten JVM tests and six emulator tests passing. On 19 November 2026 a Linux JVM run passed the contract tests, including both directions between Emilio's engines and `HybridCrypto` for all four profiles. The 30-repetition benchmark completed on that JVM. No handset was attached, so the emulator suite was not repeated.

## Pending validation

- Two-device testing with active SIMs, including delivery reports, permission behavior and sender number normalization across carriers. No new physical-device failure was available to reproduce.
- Android Keystore timings for the registered engines. The published benchmark uses in-memory keys.
- The registered suite encrypts to the recipient and authenticates envelope integrity. Sender signatures, key rotation and default SMS handler behavior are outside the demo implementation.
