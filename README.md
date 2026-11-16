# LIS4062 SecureSMS

Final project for **LIS4062 — Information Security (Autumn 2026)**:
**Secure SMS Encryption Using RSA and ECC & SSL/TLS Wireshark Analysis**.

The project combines an Android SMS application with public-key cryptography
experiments and network-security analysis. The work is due **November 25,
2026**.

## Team responsibilities

- **Axel** — Android application, graphical user interface, SMS sending and
  receiving, and integration of the project components.
- **Emilio** — RSA/ECC implementation, experimental testing, and comparison of
  encryption and decryption times.
- **Luis** — SSL/TLS analysis with Wireshark, blockchain/Bitcoin research, and
  documentation.

## Repository layout

| Directory | Purpose |
| --- | --- |
| [`android-app/`](android-app/) | Android application source and resources |
| [`crypto-benchmark/`](crypto-benchmark/) | RSA/ECC experiments and benchmarks |
| [`wireshark-analysis/`](wireshark-analysis/) | SSL/TLS captures, observations, and analysis |
| [`blockchain-research/`](blockchain-research/) | Blockchain and Bitcoin research |
| [`docs/`](docs/) | Project documentation and reports |
| [`demo/`](demo/) | Demonstration materials |

The directories currently contain placeholders only. Application and
cryptography code will be added in the corresponding feature branches.

## Branch and contribution workflow

Work is organized into these branches:

- `feature/android-app`
- `feature/crypto-benchmark`
- `feature/wireshark-blockchain`

Open a pull request from a feature branch into `main` for review and
integration. Keep `main` stable and use focused commits that describe one
change at a time.

## Security and research scope

This repository is for an academic project. Do not commit private keys,
personal SMS messages, credentials, device configuration, or sensitive packet
captures. Use sanitized sample data in demonstrations and documentation.
