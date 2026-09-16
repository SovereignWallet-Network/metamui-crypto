# ML-KEM — genuine upstream KAT (FIPS 203 conformance gate)

This directory holds **NIST-authoritative** ML-KEM Known-Answer-Test vectors
(ACVP, FIPS 203 final). It exists to answer the one question nothing else in
the tree answered for ML-KEM:

> Does our ML-KEM port reproduce, byte-for-byte, the `ek`/`dk`/`c`/`K` that the
> *real* FIPS 203 standard produces from the same `(d, z)` / `m` inputs?

## Why this is needed

`test-vectors/ml-kem/nist-kat.json` is **self-generated** — it only proves the
language bindings agree with **each other** under MetaMUI's in-house
`d := seed`, `z := SHA3-256(seed ‖ "z_derivation")` convention. That is the
same circular-KAT trap documented for SMAUG-T, AIMer, Falcon, and HQC. Worse,
the in-tree implementation was a CRYSTALS-Kyber **Round-3** port that did not
match FIPS 203 final at all; the prior "Finding #28 closed" status had been
satisfied only by a thin wrapper over the third-party `fips203` crate (since
removed). See `../ml-kem/acvp-fips203/README.md` for the full audit trail.

## Source (pinned for reproducibility)

These are NIST ACVP FIPS 203 vectors, mirrored from
[`GiacomoPope/kyber-py`](https://github.com/GiacomoPope/kyber-py) (the same
mirror convention used by `test-vectors/ml-dsa/`), then **trimmed to the first
5 `tcId`** per file. The full-fidelity copies live in
`../ml-kem/acvp-fips203/` (keyGen 25, encaps 25, decaps 10 per variant).

| Field | Value |
|---|---|
| Upstream repo | `https://github.com/GiacomoPope/kyber-py` |
| Upstream commit | `897923667b2fa80afcf910fc8c1825dddf54a97d` |
| ACVP vsId | 42 |
| ACVP revision | FIPS203 |
| Format | JSON (NIST ACVP ships ML-KEM KATs as JSON, not `.rsp`) |

```
ml-kem-512/   keygen.json   encapdecap.json
ml-kem-768/   keygen.json   encapdecap.json
ml-kem-1024/  keygen.json   encapdecap.json
```

Each file preserves the ACVP envelope (`standard`, `source`, `source_commit`,
`parameter_set`) verbatim. `keygen.json` carries 5 keyGen records
(`d, z → ek, dk`); `encapdecap.json` carries 5 encaps records
(`ek, m → c, K`) and 5 decaps records (group `dk` + `c → K`).

Verify integrity with `shasum -a 256 -c SHA256SUMS`.

## Sizes (FIPS 203)

| Variant | `ek` | `dk` | `c` | `K` |
|---|---|---|---|---|
| ML-KEM-512  |  800 | 1632 |  768 | 32 |
| ML-KEM-768  | 1184 | 2400 | 1088 | 32 |
| ML-KEM-1024 | 1568 | 3168 | 1568 | 32 |

## The gate

Each binding's gate reproduces every record deterministically through the
native FIPS 203 `(d, z)` / `m` interface and compares byte-for-byte. Behaviour
mirrors the AIMer/Falcon/HQC gates — three tiers:

- file **absent** → SKIP loudly (suite stays green);
- file present but carrying a **self-generated marker**
  (`"MetaMUI cross-language consensus"`) → FAIL (anti-circularity guard);
- file present and genuine (`"standard": "FIPS 203"` + the kyber-py source) →
  reproduce **every** record; any mismatch FAILS.

### Status

All ten bindings reproduce these vectors byte-for-byte. The table was last
accurate in mid-2026, when only the Rust row had landed; the re-ports finished
in PR #75 (commit `8ed77f0ae`) and the TypeScript/WASM gate was wired into
`scripts/node_upstream_gates.sh` in the 2026-09 audit work.

| Binding | Gate | Status |
|---|---|---|
| Rust | `metamui-mlkem/tests/mlkem_upstream_kat.rs` | PASSING |
| C | `metamui-mlkem/tests/test_mlkem_upstream_kat.c` (ctest) | PASSING |
| Swift | `MetaMUIMLKemUpstreamGate` (`tools/swift-review/upstream_gates.sh`) | PASSING |
| Go | `mlkem/mlkem_upstream_kat_test.go` | PASSING |
| Java | `id.metamui.crypto.mlkem.MLKemUpstreamKatTest` | PASSING |
| Kotlin | `mlkem/` upstream KAT test | PASSING |
| Python | `tests/test_mlkem_upstream_kat.py` | PASSING |
| C# | `MetaMUI.Crypto.MLKEM.Tests/MLKemUpstreamKatTests.cs` | PASSING |
| TypeScript / WASM | `tests/test-upstream-kat-mlkem.cjs` (TypeScript tree) | PASSING (45 records) |

Every gate FAILS rather than skips when a vector file is absent: the vectors
are tracked here, so their absence is a broken checkout.

The Rust canonical engine (`metamui_mlkem::mlkem{512,768,1024}`) is a byte-exact
FIPS 203 implementation with no third-party crate; the other nine are ports of
it, each proved against these vectors rather than against Rust.

## Re-sync TODO

If a discrepancy is ever found vs the authoritative `usnistgov/ACVP-Server`,
the upstream wins — re-fetch, re-pin the commit, refresh these JSON files +
`SHA256SUMS`, and re-run every binding's gate.

## FIPS203-tr1 (2026-09-05): seed-format decapsulation and the §7 key checks

`ml-kem-*/encapdecap-tr1.json` is the NIST ACVP **FIPS203-tr1** revision of
`ML-KEM-encapDecap` (`usnistgov/ACVP-Server`
`gen-val/json-files/ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json`,
SHA-256 in the file), untrimmed: 25 encapsulations, 20 decapsulations in the
`seed` key format (`d`, `z` → `ek`, `dk`; ten of the ciphertexts are modified
and must decapsulate to the implicit-rejection secret), and the two key-check
groups the tr1 revision introduced — `encapsulationKeyCheck` (FIPS 203 §7.2:
every packed coefficient below q) and `decapsulationKeyCheck` (§7.3: the
embedded `H(ek)`), five accept and five reject rows each. Every binding exposes
`validate_encapsulation_key` / `validate_decapsulation_key` (spelling per
language) and its gate asserts the `testPassed` verdict for every row; a
must-reject key that is accepted fails the gate. `flat/encapdecap-tr1.tsv`
(regenerate with `gen_flat_tr1.py`) is the line-based form for C, Java and
Kotlin. The original `encapdecap.json` / `keygen.json` (FIPS203, kyber-py
mirror) stay as they are.
