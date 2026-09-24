# SMAUG-T v1.2.0 KAT (the authors' own vectors)

The Known-Answer-Test records shipped by CryptoLab Inc. with reference implementation
**v1.2.0** (specification v260521, 2026-05-21) of the KpqC-winning SMAUG-T KEM, copied
verbatim from `SMAUG-T-1.2.0/kat/PQCkemKAT_smaugt_mode{1,3,5,t}.rsp` into JSON.

## Provenance

| Field | Value |
|---|---|
| Upstream | https://www.kpqc.cryptolab.co.kr/smaug-t — "Reference Implementation Version 1.2.0" |
| Archive SHA-256 | `ccb58f42043296174e10fc7af520f0a49076d8c2245bd8e66d1b88bcae568c90` |
| Vendored tree | `metamui-crypto-reference/c/cryptoLabInc-SMAUG-T-v1.2.0/` (see its `PROVENANCE.md`) |
| Vendored | 2026-09-05 |
| Generator | `tools/smaug-t-upstream-gen/genrun.sh` — rebuilds the tree's own `PQCgenKAT_kem`, refuses to vendor unless its output is byte-identical to the shipped `.rsp`, then converts |

## File layout

| File | Variant | NIST level | pk / sk / ct / ss bytes | Vectors |
|---|---|---|---|---|
| `smaugt-mode1-v1.2.0-kat.json` | SMAUG-T1 | 1 | 672 / 832 / 672 / 32 | 100 |
| `smaugt-mode3-v1.2.0-kat.json` | SMAUG-T3 | 3 | 1088 / 1312 / 992 / 32 | 100 |
| `smaugt-mode5-v1.2.0-kat.json` | SMAUG-T5 | 5 | 1440 / 1728 / 1376 / 32 | 100 |
| `smaugt-modet-v1.2.0-kat.json` | SMAUG-TiMER | 1 | 672 / 832 / 608 / 32 | 100 |

Each record: `count`, `seed` (48-byte NIST AES-256-CTR-DRBG seed), `pk`, `sk` (full KEM sk
including the 32-byte `t` and the embedded pk), `ct`, `ss`. The randomness model is the NIST
`PQCgenKAT_kem` one: `randombytes_init(seed)` once per record, then keygen and encaps draw from
the same DRBG.

## Why v1.1.1 was replaced

v1.2.0 fixes `load64_littleendian` in `src/dg.c`: v1.1.1 wrote every unpacked block of the
SHAKE tape to the same ten words, so coefficients 64..255 of each discrete-Gaussian polynomial
were sampled from zeros. Wire sizes are unchanged; every pk/sk/ct/ss byte differs for the same
seed. The v1.1.1 records are therefore not a valid oracle for any implementation of the
standard as published, and were deleted rather than kept beside these.
