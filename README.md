# MetaMUI Crypto

Portable post-quantum cryptography for applications and blockchains.

## Status

This private repository is being prepared for a public release. It currently contains an introductory README only; implementation code, packages, and installation instructions will follow after release verification.

## Purpose

MetaMUI Crypto will make the cryptography used by MetaMUI available through small, consistent APIs and reusable packages. The library is intended to be useful independently of the MetaMUI blockchain.

The release goal is broad coverage of completed, verified PQC implementations, with particular attention to Korean PQC and interoperability across languages.

## Planned coverage

- All cryptographic algorithms used by MetaMUI, including the exact Falcon implementation, parameters, and encodings used in deployed integrations.
- NIST-standardized PQC algorithms, including ML-KEM, ML-DSA, and SLH-DSA.
- Korean PQC families, including AIMer, HAETAE, NTRU+, and SMAUG-T.
- Additional completed implementations as they satisfy the release criteria.

Falcon variants and any future FN-DSA implementation will be identified separately. Algorithm selection, standardization status, and implementation validation will be documented independently; inclusion will not imply certification or an independent security audit.

## Language and distribution goals

The initial goal covers **nine programming languages plus the WebAssembly runtime**:

| Languages | Runtime |
| --- | --- |
| Rust, C, Swift, Go, Python, TypeScript, Kotlin, Java, C# | WebAssembly |

Support may use native implementations, FFI bindings, or WebAssembly. A published support matrix will distinguish these approaches and report tested algorithms, platforms, and package versions.

Distribution will begin with Rust and npm packages and expand to the relevant package registries for supported languages. Registry names, availability, and installation commands will be published after release validation.

## Release preparation

- Establish an algorithm inventory and map public versions to MetaMUI consumers.
- Select release-ready source and required dependencies; review licensing and provenance.
- Define safe public APIs and stable key, signature, ciphertext, and error formats.
- Validate against authoritative test vectors and cross-language interoperability tests.
- Review security properties, platform support, and reproducible package builds.
- Publish reproducible performance baselines and prioritize measured bottlenecks.
- Add usage examples, package documentation, and a vulnerability-reporting process.

Implementation availability, test coverage, external review, and performance results will be reported separately for each algorithm and target.

## License direction

The planned public release license is **Apache License 2.0**.

The license text and applicable third-party notices will be added during release preparation. Upstream licenses and attribution requirements will be preserved.

## Related projects

- [metamui-chain](https://github.com/SovereignWallet-Network/metamui-chain) — DID relay blockchain.
- [metamui-wallet-sdk](https://github.com/SovereignWallet-Network/metamui-wallet-sdk) — Wallet and token application SDK.
