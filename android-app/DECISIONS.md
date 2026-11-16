# Android design decisions

- **Compose and StateFlow.** A single activity renders observable Room history and interacts with a ViewModel. An application-scoped service owns inbound processing so the receiver and UI share the same protocol.
- **Separate crypto and transport.** Engines work with authenticated contexts and typed results. SMS only receives versioned frames from a carrier-capable suite. The two simulated users can exercise the pipeline offline using explicitly insecure demo data.
- **Independent SMS frames.** The app controls reassembly and tracks every physical SMS explicitly. A carrier may charge for each frame. Delivery reporting depends on the carrier.
- **Local Room history.** Metadata and bounded pending fragments are stored locally. Message bodies are sealed with a separate Android Keystore AES-GCM key. No cloud service or backup is used. Phone numbers, timestamps, sizes and status remain queryable in Room.
