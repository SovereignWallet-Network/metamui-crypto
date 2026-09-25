# Ascon (NIST SP 800-232) genuine-upstream oracle

Vendored, unmodified, from the Ascon authors' reference implementation
[ascon/ascon-c](https://github.com/ascon/ascon-c) at commit `446347f21b209f3921c65ece70027c366cbe1693`
(submodule `metamui-crypto-reference/c/ascon-ref`) by
`tools/ascon-upstream-gen/genrun.sh`, which first rebuilds the reference's own
`genkat_{aead,hash,cxof}` against the `ref/` sources and refuses to vendor
unless the regenerated output is byte-identical to the shipped file.

| Function | Reference directory | File | Records |
|---|---|---|---|
| Ascon-AEAD128 | `crypto_aead/asconaead128` | `aead128/LWC_AEAD_KAT_128_128.txt` | 1089 (PT 0–32 B × AD 0–32 B) |
| Ascon-Hash256 | `crypto_hash/asconhash256` | `hash256/LWC_HASH_KAT_128_256.txt` | 1025 (Msg 0–1024 B) |
| Ascon-XOF128 | `crypto_hash/asconxof128` | `xof128/LWC_XOF_KAT_128_512.txt` | 1025 (Msg 0–1024 B, 64 B out) |
| Ascon-CXOF128 | `crypto_cxof/asconcxof128` | `cxof128/LWC_CXOF_KAT_128_512.txt` | 1089 (Msg 0–32 B × Z 0–32 B, 64 B out) |

Record format is the LWC one: `Count = n`, then `Key`/`Nonce`/`PT`/`AD`/`CT`
(AEAD, `CT` = ciphertext ‖ 16-byte tag), `Msg`/`MD` (hash, XOF) or
`Msg`/`Z`/`MD` (CXOF), all upper-case hex, blank line between records.
Inputs are the incrementing byte pattern 00 01 02 …; `Key` is
000102…0F and `Nonce` 101112…1F.

Every binding's SP 800-232 gate replays all four files in full and FAILS —
never skips — when a file is absent. `SHA256SUMS` is checked by
`tools/swift-review/lint_test_vectors.py`.
