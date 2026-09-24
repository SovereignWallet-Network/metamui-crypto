# SLH-DSA genuine-upstream ACVP gate

These are **genuine NIST ACVP test vectors** for SLH-DSA (FIPS 205), used as an
independent conformance oracle by every language binding's upstream gate.

## Provenance

Reduced subset of
[`usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server)
`gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205` (the
`prompt.json` inputs merged with the matching `expectedResults.json` answers).

| File | Groups | Tests | Covers |
|---|---|---|---|
| `keygen.json` | 12 | 120 | all 12 parameter sets, 10 keypairs each |
| `siggen.json` | 72 | 72 | 1 signature per group → every (paramSet × deterministic/hedged × external/internal × pure/preHash) combination |
| `sigver.json` | 36 | 72 | 1 accept + 1 reject per group |

All 12 parameter sets are present: `SLH-DSA-{SHAKE,SHA2}-{128,192,256}{s,f}`.

## Why these and not the sibling `test-vectors/slh-dsa/` files

The `test-vectors/slh-dsa/slh_dsa_*_vectors.json` files were generated **by the
MetaMUI Rust implementation itself** (`"source": "metamui-slhdsa canonical Rust
implementation"`) and only ever covered the 6 SHAKE sets. They prove
self-consistency, not FIPS 205 conformance — and being SHAKE-only they never
exercised the SHA2 hash family, which was found to be entirely non-conformant
(wrong `ADRSc` compression, invented domain-separator bytes, plain-hash instead
of HMAC `PRF_msg`, flat instead of nested-MGF1 `H_msg`, and no SHA-512 at
categories 3/5). These upstream vectors are an external oracle: a mismatch is a
genuine bug.

## Consumer contract

- Treat as immutable inputs in CI.
- Hex is **UPPERCASE** in the ACVP source; compare case-insensitively.
- `signatureInterface`: `internal` consumes the message directly as `M'`;
  `external` builds `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M` (pure) or
  `M' = 0x01 ‖ len(ctx) ‖ ctx ‖ OID(hashAlg) ‖ PH(M)` (preHash).
- `deterministic: true` ⇒ `opt_rand = PK.seed`; `false` ⇒
  `opt_rand = additionalRandomness` (supplied per test).

## Regenerate

Download the three folders from ACVP-Server and re-run the reducer described in
the project history (1 sigGen test/group, accept+reject pair per sigVer group,
all keyGen). Verify against `SHA256SUMS`.
