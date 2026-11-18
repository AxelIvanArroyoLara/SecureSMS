# SecureSMS for Android

SecureSMS is the Android application for the LIS4062 Information Security project. It transports encrypted payloads across ordinary SMS and includes an offline two-user demonstration of the same framing and application pipeline.

## Run locally

Open `android-app/` in Android Studio. Use the bundled Gradle wrapper, a JDK 25 Gradle runtime, and Android SDK 37. Select an Android 8.0 or newer device (API 26+), then run the `app` debug configuration. Run the following commands from this directory.

```sh
./gradlew testDebugUnitTest
./gradlew assembleDebug
./gradlew connectedDebugAndroidTest
```

The APK is at `app/build/outputs/apk/debug/app-debug.apk`.

## Offline demonstration

1. Open **Offline demo** and choose **Open as Alice**.
2. Tap **Encryption** to choose an RSA or ECC profile and a delivery scenario. Return to the inbox tab to resume the chat.
3. Write and send a message. For multipart behavior, use approximately 150 or more ASCII characters.
4. Tap **Open as Bob** to read the reconstructed message. Try **Reorder + duplicate** for a successful recovery or **Missing segment** and **Send failure** to inspect failures.
5. Tap a message to inspect the recorded encryption or decryption duration, segment count and byte sizes.

The demo applies a reversible test transform. Use sample text. No carrier SMS or SMS permissions are needed in this mode.

## Carrier SMS

Use two consenting Android devices with active SIMs and a test installation that grants restricted SMS permissions. Carrier rates apply per segment. This app uses the platform APIs for a non-default SMS app. The normal SMS app may also receive or display the encrypted frames. Store distribution policies and the installer may restrict access.

1. Select **Carrier SMS** in the inbox. In **Encryption**, request both SMS permissions and set an active default SMS subscription in Android if required.
2. On both devices, choose the same profile and use **Keys** to generate a local key. ECC requires Android 12 or newer. Share the public key text with the other device.
3. Import each recipient's key against their E.164 number, such as `+525512345678`. Compare the full SHA-256 fingerprint through a trusted channel, then mark it verified.
4. Start the conversation or open the one created by import. Send a short test message explicitly. On the recipient, open Carrier SMS and check the chat. Confirm outgoing sent/delivery status and incoming decryption diagnostics.
5. Repeat in both directions, then test a longer message and a mismatched recipient key. Carrier delivery reports are optional. A sent state with no delivery report can persist.

Physical-device carrier operation is pending validation. There is no sender signature, automatic trust or key rotation. Carriers see addresses, timing, SMS counts and ciphertext. Recovery after app data deletion requires fresh key exchange. Transient demo fragments use publicly reversible test bytes.

## Code and specifications

The Kotlin app uses Jetpack Compose and Material 3, an Android ViewModel and StateFlow, Room, Android Keystore, and explicit app-level dependency wiring. `domain/` coordinates messaging, `crypto/` contains the engine contract and adapters, `protocol/` validates and reconstructs envelopes, `transport/` wraps SMS and simulation, and `data/` persists records and receipts.

- [Crypto integration](CRYPTO_INTEGRATION.md)
- [SMS wire protocol](SMS_PROTOCOL.md)
- [Testing](TESTING.md)
- [Design decisions](DECISIONS.md)
- [Project state](STATE.md)
