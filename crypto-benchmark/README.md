# RSA and ECC benchmark

This directory holds Emilio's cryptographic measurements for SecureSMS. The contract and the experiment plan are in [CONTRACT.md](CONTRACT.md). The English methodology, results, and limitations for the report are in [RESULTS.md](RESULTS.md).

The application engines live in `android-app` so the benchmark calls the same classes the app registers. `results/` contains one row per repetition, the median/mean/standard-deviation summary, the machine record, and the charts.

From the repository root:

```sh
./crypto-benchmark/run-benchmark.sh
```

That command runs `HybridBenchmarkTest` with `-Pbenchmark=true`. A normal `./gradlew testDebugUnitTest` skips that test. The run takes several minutes because RSA-7680 key generation is part of the isolated block.

The committed numbers are a JVM run with in-memory keys. They are not Android Keystore timings. A later phone run has to be stored separately and labeled with the device.
