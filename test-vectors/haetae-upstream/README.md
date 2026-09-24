# HAETAE — genuine upstream KAT (conformance gate)

This directory holds the **unmodified** Known-Answer-Test vectors produced by the
official **HAETAE v1.2.0** reference implementation (CryptoLab Inc., specification
v260825 of 2026-08-25, the KpqC-winner revision aligned to Korean standard
**KS X 123456**). It exists to answer the one question
nothing else in the tree answers:

> Does our HAETAE port produce/accept exactly what the *real* upstream HAETAE does?

## Why this is needed

HAETAE is a **KpqC** / NIST additional-signatures Round-1 candidate. It is **not**
FIPS-standardized, so — unlike ML-KEM / ML-DSA / SLH-DSA — **NIST ACVP/CAVP
publishes no test vectors for it**. The authoritative external ground truth is the
reference `PQCsignKAT_*.rsp` files produced by the submission's
`kat/PQCgenKAT_sign.c` (NIST AES-256-CTR-DRBG), exactly as `test-vectors/falcon-upstream/`
serves Falcon.

Every vector in `test-vectors/haetae/` is a cross-language **consensus** fixture —
it proves the 10 bindings agree *with each other* but cannot detect a shared
divergence from the actual HAETAE spec. These upstream `.rsp` files close that gap.

## Source (pinned for reproducibility)

Vendored upstream reference (already in this repo, fully offline-reproducible):

- Tree: `metamui-crypto-reference/c/cryptoLabInc-HAETAE-v1.2.0/` (reference
  implementation v1.2.0 + the authors' `kat/`), vendored from the official
  `HAETAE.zip` published at kpqc.cryptolab.co.kr — see its `PROVENANCE.md`.
- `HAETAE.zip` SHA-256:
  `e54f8f962eefadbb2929bca292797bc7ca18769fb9a273c10204f3887fd83e84`
- The `.rsp` files here are the archive's own published KAT
  (`kat/PQCsignKAT_haetae_mode{2,3,5}.rsp`). `tools/haetae-upstream-gen/genrun.sh`
  rebuilds the reference's own generator per mode and refuses to vendor unless
  its output is byte-identical to the shipped file — the oracle is never a
  generator we wrote. See `SHA256SUMS` for per-file digests.

### `v1.1.2-verify-only/` — the previous release, verify-only

v1.2.0 changed only the hyperball sampler (`sampler.c`: 83-bit CDT, degree-10
`approx_exp`, 26-byte draws, ceiling `smulh48`). Keys are unchanged and the
verifier is unchanged, so every signature the 1.1.2 reference produced must
still verify under v1.2.0 while no longer being what a v1.2.0 signer emits.
`v1.1.2-verify-only/haetae{2,3,5}/` holds the 1.1.2 archive's KAT files
(same seeds, same pk/sk, 1.1.2 signatures; archive SHA-256
`9b69afb55ed96a20d9626b3ea729c291f9e4bfd8d880b740fcb30f6955c4ca72`, GitHub
tag `HAETAE-1.1.2` in `metamui-crypto-reference/c/haetae-ref/`). The Rust gate
verifies all 300 and asserts every signature differs from its v1.2.0
counterpart. Kept for one release, then deleted.

## Vector format (HAETAE v1.2.0, KS X 123456)

`PQCgenKAT_sign.c` seeds `randombytes_init(seed, NULL, 256)` (AES-256-CTR-DRBG)
from the 48-byte per-count `seed`, then draws, in order:

```
keygen_seed (32 bytes)   -> crypto_sign_keypair_internal(pk, sk, keygen_seed)
rnd         (32 bytes)   -> signing randomness (hedged)
ctxlen      (1 byte)     -> length of context string
ctx         (ctxlen)     -> context string
pre = (ctxlen || ctx)    -> prefix bound into the message hash
```

Signing is **detached** (`sig`, `siglen`) and **context-bound**:

```
mu      = SHAKE256(sk_pubkey_part || pre || m)        # absorb-thrice
seedbuf = SHAKE256(key || rnd || mu)                  # hedged signing seed
c       = challenge(highbits, lsb, mu)
```

Each record: `count`, `seed` (48B), `mlen`, `msg`, `pk`, `sk`, `siglen`, `sig`.
This is **not** the old combined-`sm` NIST API — HAETAE emits a detached signature
plus an explicit context. Parameter sizes:

| Mode | K | L | pk bytes | sk bytes | sig bytes (max) |
|------|---|---|----------|----------|-----------------|
| 2    | 2 | 4 | 992      | 1408     | 1474            |
| 3    | 3 | 6 | 1472     | 2112     | 2349            |
| 5    | 4 | 7 | 2080     | 2752     | 2948            |

100 counts per mode, `mlen = 33 * (count + 1)`.

## Regenerate

```sh
bash tools/haetae-upstream-gen/genrun.sh
```

It builds `metamui-crypto-reference/c/cryptoLabInc-HAETAE-v1.2.0/reference_implementation`
per mode, runs the reference's own `PQCgenKAT_sign`, `cmp`s the output against
the archive's shipped `kat/*.rsp`, and only then copies the files here and
rewrites `SHA256SUMS`.
