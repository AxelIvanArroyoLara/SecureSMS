# SecureSMS testing

## Commands

Run from `android-app/`.

```sh
./gradlew testDebugUnitTest
./gradlew assembleDebug
./gradlew connectedDebugAndroidTest
```

The project uses an Android SDK 37 installation, Android Studio's JDK 25 and the Gradle 9.6 wrapper. The local run used Gradle's offline dependency cache on an Apple Silicon Mac. A headless, read-only Medium Phone emulator ran Android 17 / API 37.

## Results

| Command | Result |
| --- | --- |
| `./gradlew testDebugUnitTest` | 10 passed |
| `./gradlew assembleDebug` | Debug APK built successfully |
| `./gradlew connectedDebugAndroidTest` | 6 passed on the API 37 emulator |

The first Compose run caught a reentrant list-layout crash while switching demo users. The fix schedules scrolling for the next layout pass. A subsequent run exposed a test tap that could race the keyboard animation. The final test uses the button's semantic action for sending and asserts the visible results. A separate APK install and cold launch showed the offline inbox.

## Coverage

| Suite | Coverage |
| --- | --- |
| `ProtocolTest` | Maximum-size round trip, canonical frames, malformed input, unsupported version/suite, reordering, duplicates, mixed routes and expiration |
| `CryptoTest` | Registry and missing engines, reference hybrid profiles, Emilio engines against that reference in both directions, invalid keys and ciphertext, authenticated metadata, and the deterministic mock |
| `HybridBenchmarkTest` | Skipped unless `-Pbenchmark=true`. Writes the 30-repetition CSV under `crypto-benchmark/results/` |
| `SimulationTest` | Incoming fragments, ordering, duplicate receipts, dropped fragment and failed send |
| `AndroidPipelineTest` | Room reopen, contact associations, status aggregation, simulation loopback, local history protection and the carrier transport's mock rejection, verified-key gate, decryption failures, Android Keystore round trips |
| `DemoUiTest` | Start a conversation, compose and send, switch recipients, read the recovered message and inspect diagnostics |

Test reports are under `app/build/reports/tests/testDebugUnitTest/` and `app/build/reports/androidTests/connected/debug/`.

## Manual checks

- Open **Offline demo** as Alice. Send a multipart message using **Reorder + duplicate**, then switch to Bob. Verify one received message and inspect encryption and decryption diagnostics on the corresponding copies.
- Repeat with **Missing segment** and **Send failure**. The outgoing record should report a failure and Bob should receive no new complete message.
- For physical testing, follow the carrier setup in [README](README.md). Test RSA and ECC on two compatible devices, both directions, including a long message and a denied-permission case. Compare both payloads and callback statuses. An emulator can validate the application and Keystore but cannot establish carrier delivery behavior.

On 19 November 2026, `./gradlew testDebugUnitTest` on Linux passed 11 tests and skipped `HybridBenchmarkTest`. `./gradlew assembleDebug` produced the debug APK. `connectedDebugAndroidTest` was not repeated: `adb devices` listed no handset or emulator. The benchmark was run separately with `-Pbenchmark=true` and is summarized in `crypto-benchmark/RESULTS.md`.

Carrier sending, reception and delivery reports on physical SIMs remain unverified. JVM interoperability between Emilio's engines and the reference hybrid is covered by `CryptoTest`. A Keystore run on a device is still outstanding.
