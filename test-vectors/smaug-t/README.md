# SMAUG-T Test Vectors

One track, one algorithm. Everything here attests CryptoLab's **reference
implementation v1.2.0** (specification v260521, 2026-05-21), which is what all
ten language bindings implement.

| Subdirectory | Provenance | Use for |
|---|---|---|
| [`v1.2.0-kat/`](v1.2.0-kat/) | The authors' own `kat/PQCkemKAT_smaugt_mode{1,3,5,t}.rsp` from the v1.2.0 archive (SHA-256 `ccb58f42…`), converted by `tools/smaug-t-upstream-gen/genrun.sh` after it rebuilt the reference's generator and checked the output byte-for-byte. 100 vectors × 4 modes (T1, T3, T5, TiMER). | Byte-equality against the published algorithm — pk, sk, ct, ss and decap, all 400 vectors, in every binding. |
| [`v1.1.1-packring/`](v1.1.1-packring/) | Intermediate state captured from the v1.1.1 C reference, built with `-DSMAUGT_CONFIG_MODE` for each of `SMAUGT_MODE{1,3,5,T}`. The packing layer is unchanged in v1.2.0. | Unit-level ground truth for the `R2_q` bit-packing layer, verified byte-for-byte by `metamui-smaug-t/tests/pack_ring_v1_2_0.rs` (Rust) and `metamui-crypto-c/metamui-smaug-t/tests/test_smaug_t_packring_fixtures.c` (the in-house C, every width 3–11). |

## v1.1.1 → v1.2.0 (2026-09-05)

`v1.1.1-kat/` was replaced, not kept beside the new oracle. v1.2.0 fixes
`load64_littleendian` in `src/dg.c`: v1.1.1 wrote every unpacked block of the
SHAKE tape to the same ten words, so coefficients 64..255 of each
discrete-Gaussian polynomial were sampled from zeros — three quarters of the
MLWE error. Every pk/sk/ct/ss byte differs for the same seed; wire sizes do
not. A KAT set that certifies that bug is not evidence of anything the
project wants to ship, so it went, together with the vendored v1.1.1 tree.

## What was removed on 2026-09-05, and why

Until then this directory carried three tracks, two of which attested an
algorithm the project no longer ships. The Rust crate's public `SmaugT` API
routed to a 2023 draft core (power-of-two moduli q=1024/2048) whose wire format
matched no other binding; that core is deleted and `SmaugT` is now a facade over
the v1.1.1 KEM. Its vectors went with it:

| Removed | Why |
|---|---|
| `upstream-kat/` | Vendored from [hmchoe0528/SMAUG-T_public](https://github.com/hmchoe0528/SMAUG-T_public) @ `2c039df23` (2023). That upstream repo is deprecated, and the reference in it does not reproduce its own KAT — which is what the v1.1.1 release fixed. It attested only the deleted draft core. The `c-ref-ground-truth/v1.1.1-packring/` fixtures inside it were genuine v1.1.1 ground truth misfiled under a deprecated-repo name; they were moved to `v1.1.1-packring/`, not deleted. |
| `clean-kat/` | No consumer in any of the ten bindings. |
| `vectors.json`, `test-vectors.json`, `vectors-compact.json`, `kpqc-format-vectors.json`, `cross-language-report.json` | Output of an in-tree Python implementation, round-trip-only, carrying no external attestation — and `expected_pk_hash` in `vectors-compact.json` was fabricated as `SHA256(seed + "PK")[:8]` rather than a hash of real keygen output. No consumer remained in any binding. |

The `metamui-crypto-reference/c/smaug-t-ref` submodule, which pointed at the
same deprecated upstream, was removed in the same change.

## Versions

There is no "SMAUG-T v4.0" — that version never existed. The versions that
exist are v1.1.1 (2026-04-30, superseded) and v1.2.0 (2026-05-21, implemented).
