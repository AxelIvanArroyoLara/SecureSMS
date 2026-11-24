#!/bin/sh
# Re-run the hybrid and isolated measurements. Raw rows land in results/.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
cd "$root/android-app"
./gradlew testDebugUnitTest --tests com.example.securesms.HybridBenchmarkTest -Pbenchmark=true "$@"
