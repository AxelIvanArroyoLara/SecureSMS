# Android application state

Development is on `feature/android-app`. The Android Gradle project and application sources are contained in `android-app/`. The benchmark and research directories are independent.

## Implemented

- Compose inbox and chat, two-user offline demo, encryption configuration, key management and diagnostics.
- Room conversations, messages, contacts, identities, per-segment receipts and bounded pending fragments. Keystore seals message bodies. Interrupted complete batches can resume from Room.
- Android SMS send, receive and status callbacks gated by permissions, SIM selection, a carrier-capable crypto suite and a verified recipient key.
- Crypto engine contract and RSA/ECC reference adapters. The deterministic demo transform is confined to its own transport and suite.

## Verified

The debug APK builds and cold-launches on the API 37 emulator. Ten JVM tests and six emulator tests pass, including hybrid round trips with all four profiles, Room restart persistence and the end-to-end offline Compose flow.

## Pending validation

- Two-device testing with active SIMs, including delivery reports, permission behavior and sender number normalization across carriers.
- Integration and bidirectional interoperability with Emilio's RSA and ECC implementations.
- The reference suite encrypts to the recipient and authenticates envelope integrity. Sender signatures, key rotation and default SMS handler behavior are outside the demo implementation.
