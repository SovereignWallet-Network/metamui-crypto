# ML-DSA — genuine upstream KAT (FIPS 204 conformance gate)

NIST-authoritative ML-DSA Known-Answer-Test vectors (ACVP, **FIPS 204 final**).
This directory answers the question the keyGen-only `test-vectors/ml-dsa/`
corpus could not: does each binding reproduce, byte-for-byte, the `pk`/`sk`/
`signature` that the *real* FIPS 204 standard produces — for **keyGen,
sigGen, and sigVer**, not just key generation?

## Why this is needed

`test-vectors/ml-dsa/ml-dsa-*-kat.json` carries only **keyGen** vectors
(mirrored from `GiacomoPope/dilithium-py`). Nothing in the tree tested whether
our *signing* and *verification* match NIST. That is the same incomplete-KAT
gap documented for ML-KEM, HQC, Falcon, AIMer. FIPS 204 signing diverges from
the older CRYSTALS-Dilithium Round 3 spec in ways that break byte-equality
(tr = 64 B, commitment c̃ = 32/48/64 B per level, ρ″ = H(K‖rnd‖μ), and a
context-string / domain-separated pre-hash API), so a Round-3 core can pass a
keyGen check yet still produce non-conformant signatures.

## Source (pinned for reproducibility)

| Field | Value |
|---|---|
| Upstream repo | `https://github.com/usnistgov/ACVP-Server` |
| Path | `gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json` |
| Revision | FIPS204 (final) |
| Format | JSON (ACVP `internalProjection`: testGroups → tests) |
| Trim | keyGen ≤5 tests/group; sigGen ≤2 tests/group (incl. empty-context); sigVer ≤4 tests/group |

```
keygen.json   3 groups (ML-DSA-44/65/87), seed → pk, sk
siggen.json   24 groups: {deterministic|hedged} × {internal|external} × {pure|preHash|externalMu}
sigver.json   12 groups: external/internal × pure/preHash, mix of testPassed true/false
```

## Group selectors (FIPS 204 API surface)

Each sigGen/sigVer group is tagged with `signatureInterface` (internal|external),
`preHash` (none|pure|preHash), `externalMu`, and `deterministic`. The
**external + pure + deterministic + empty-context** subset is the part a minimal
`sign(sk,msg)` / `verify(pk,msg,sig)` API can reach. Non-empty context, the
internal interface, `externalMu`, and HashML-DSA (`preHash`) require a
context-aware / internal entry point — see each binding's gate test for which
rows it currently exercises.

## `flat/` — derived TSV fixtures for the line-based gates

The C / Java / Kotlin upstream gates parse line-based vectors (as their
`falcon-upstream` gates do), not nested JSON. `flat/{keygen,siggen,sigver}.tsv`
are generated from the JSON above by `gen_flat_fixture.py` — the **JSON files
remain the source of truth**; regenerate after any JSON change:

```
python3 gen_flat_fixture.py
```

Tab-separated, lowercase hex, empty fields empty. `preHash` rows carry the
precomputed DER OID and `PH(M)` digest so a gate needs no SHA-2/3 of its own:

- `keygen.tsv` : level, seed, pk, sk
- `siggen.tsv` : level, iface, preHash, extMu, det, ctx, oid, phm, rnd, mu, message, sig, sk
- `sigver.tsv` : level, iface, preHash, extMu, ctx, oid, phm, mu, message, pk, sig, passed

The JSON-native gates (Go, Python, TypeScript, C#, Swift, WASM) parse the JSON
directly and additionally exercise each binding's own OID/`PH(M)` wiring.

## FIPS204-tr1 (2026-09-05): `siggen-tr1.json`

`siggen-tr1.json` is the NIST ACVP **FIPS204-tr1** revision of `ML-DSA-sigGen`
(`usnistgov/ACVP-Server` `gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/internalProjection.json`,
SHA-256 in the file), trimmed to the first two tests of each of its 48 groups —
the same eight interface kinds (external pure / external preHash / internal /
internal externalMu × deterministic / hedged) for all three parameter sets, 96
signatures. Every binding's sigGen gate runs it beside `siggen.json`;
`flat/siggen-tr1.tsv` (from `gen_flat_fixture.py`) is the line-based form for
C, Java and Kotlin. The preHash groups also drive the shared
`metamui-prehash-oids` table (`hash_sign_with` / `hash_verify_with` in Rust).
