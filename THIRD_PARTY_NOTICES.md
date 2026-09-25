# Third-party notices for MetaMUI Crypto (Rust)

This file lists every third-party component that is shipped in, written
against, or redistributed with this tree, with its upstream, the revision
that was taken, its license, and the notice text that license requires. The
register that produces this list is the provenance register of the source
repository; a component that has no row there cannot be exported.

MetaMUI Crypto itself is Copyright 2024-2026 Sovereign Wallet Co., Ltd. and
licensed under the Apache License, Version 2.0 (see LICENSE). Every crate
under `metamui-crypto-rust/` is MetaMUI's own implementation; no third-party
cryptographic library is compiled into them.


## Notices carried by the Rust crates

| notice | reason | where |
|---|---|---|
| MIT — Thomas Pornin / Falcon Project (Falcon reference implementation, falcon-sign.info, Round-3 package) | `metamui-falcon512` is written against the reference and gated on its known-answer files | `metamui-crypto-rust/metamui-falcon512`, `test-vectors/falcon-upstream` |
| MIT — Thomas Prest (falcon.py, https://github.com/tprest/falcon.py) | the FFT/LDL reference module in `metamui-falcon512` follows the Python reference | `metamui-crypto-rust/metamui-falcon512/src/falcon_reference/` |
| MIT — Team SMAUG-T (SMAUG-T v1.2.0 reference, https://www.kpqc.cryptolab.co.kr/smaug-t) | `metamui-smaug-t` is a port of the reference and is gated byte-for-byte on its known-answer files | `metamui-crypto-rust/metamui-smaug-t`, `test-vectors/smaug-t` |
| MIT — Team HAETAE (HAETAE v1.2.0 reference, https://www.kpqc.cryptolab.co.kr/haetae) | `metamui-haetae` is a port of the reference and is gated on its known-answer files | `metamui-crypto-rust/metamui-haetae`, `test-vectors/haetae-upstream` |
| MIT — SAMSUNG SDS (AIMer, https://github.com/samsungsds-opensource/AIMer) | `metamui-aimer` is a port of the v3 and v2.1 references and is gated on their known-answer files | `metamui-crypto-rust/metamui-aimer`, `test-vectors/aimer-upstream` |
| MIT — NTRU+ TEAM (https://github.com/ntruplus/ntruplus, commit 621c667) | `metamui-ntru-plus` is a port of the reference and is gated on its known-answer files | `metamui-crypto-rust/metamui-ntru-plus`, `test-vectors/ntru-plus-upstream` |
| BSD-3-Clause — curve25519-dalek and schnorrkel contributors; MIT — merlin (Henry de Valence and contributors) | `metamui-sr25519` is an own port written against these references and gated on the schnorrkel-generated known-answer files | `metamui-crypto-rust/metamui-sr25519` |
| Public domain — ref10 (Daniel J. Bernstein et al., SUPERCOP) | the Ed25519 field arithmetic in `metamui-ed25519` follows ref10 | `metamui-crypto-rust/metamui-ed25519` |


## Test vectors redistributed with this tree

| corpus | upstream | license basis |
|---|---|---|
| `test-vectors/falcon-upstream/falcon512`, `falcon1024` | falcon-round3.zip (Falcon Project, NIST submission) | MIT |
| `test-vectors/falcon-upstream/falcon-padded-512`, `falcon-padded-1024` | PQClean `crypto_sign/falcon-padded-*` harness output | public domain / MIT (PQClean) |
| `test-vectors/ml-kem-upstream` | NIST ACVP FIPS 203 vectors, mirrored from GiacomoPope/kyber-py | U.S. Government work, 17 U.S.C. §105; mirror MIT |
| `test-vectors/ml-kem` | kyber-py mirror and MetaMUI-generated fixtures | MIT; own |
| `test-vectors/sha-3`, `sp800-185` | NIST ACVP / FIPS 202 examples / SP 800-185 examples | U.S. Government work |
| `test-vectors/sha-2` | NIST CAVP examples and RFC appendices | U.S. Government work; IETF Trust legal provisions (test data) |
| `test-vectors/aes`, `hmac` | Google Wycheproof | Apache-2.0 |
| `test-vectors/aes-ctr-drbg`, `falcon` | MetaMUI-generated fixtures and NIST SP 800-90A examples | own; U.S. Government work |
| `test-vectors/ml-dsa-upstream`, `slh-dsa-upstream` | NIST ACVP-Server FIPS 204 / FIPS 205 vectors | U.S. Government work, 17 U.S.C. §105 |
| `test-vectors/ml-dsa`, `slh-dsa`, `haetae` | MetaMUI-generated fixtures (cross-language consensus vectors) | own |
| `test-vectors/smaug-t` | CryptoLab SMAUG-T v1.2.0 KAT and v1.1.1 packing ground truth | MIT — Team SMAUG-T |
| `test-vectors/haetae-upstream` | HAETAE v1.2.0 / v1.1.2 KAT (`PQCgenKAT_sign`) | MIT — Team HAETAE |
| `test-vectors/aimer-upstream` | Samsung SDS AIMer v3 and v2.1 KAT | MIT — SAMSUNG SDS |
| `test-vectors/ntru-plus-upstream` | NTRU+ authors' KAT (commit 621c667) | MIT — NTRU+ TEAM |
| `test-vectors/blake3` | BLAKE3 team official test vectors | CC0-1.0 OR Apache-2.0 — BLAKE3 team |
| `test-vectors/blake2`, `hkdf` | RFC 7693 and RFC 5869 appendices | IETF Trust (test data) |
| `test-vectors/ed25519` | RFC 8032 vectors and ZIP-215 vectors | IETF Trust; MIT — Zcash (ZIP-215) |
| `test-vectors/keccak256` | Ethereum js-ethereum-cryptography suite | MIT — ethereum/js-ethereum-cryptography |
| `test-vectors/sr25519` | w3f/schnorrkel-generated KAT | BSD-3-Clause — Web3 Foundation |

`test-vectors/README.md` and each corpus's own README state the provenance
of every file.


## License texts

### MIT License — Falcon Project / Thomas Pornin

```
Copyright (c) 2017-2019  Falcon Project

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### MIT License — Thomas Prest (falcon.py) and Giacomo Pope (kyber-py)

The same MIT text as above applies, with the copyright lines
`Copyright (c) 2018 Thomas Prest` and `Copyright (c) 2023 Giacomo Pope`
respectively.

### MIT License — Team SMAUG-T, Team HAETAE, SAMSUNG SDS, NTRU+ TEAM

The same MIT text as above applies, with the copyright lines
`Copyright (c) 2026 Team SMAUG-T`, `Copyright (c) 2026 Team HAETAE`,
`Copyright (c) 2022-2026 SAMSUNG SDS` and the NTRU+ TEAM's notice
respectively (the reference archives' `LICENSE` files, recorded in the
source repository's provenance register).

### MIT License — merlin, Zcash (ZIP-215) and ethereum/js-ethereum-cryptography

The same MIT text as above applies, with the respective copyright lines of
the merlin authors, the Zcash contributors and the js-ethereum-cryptography
authors.

### BSD 3-Clause License — curve25519-dalek, schnorrkel, Web3 Foundation

```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

with the copyright lines `Copyright (c) 2016-2021 isis agora lovecruft,
Henry de Valence` (curve25519-dalek), `Copyright (c) 2017-2019 isis agora
lovecruft, Jeffrey Burdges, Web3 Foundation` (schnorrkel) and the Web3
Foundation for the generated vectors.

### CC0 1.0 Universal OR Apache License 2.0 — BLAKE3 team test vectors

The BLAKE3 team publishes its test vectors under CC0-1.0 or Apache-2.0 at
the recipient's choice; this tree takes them under Apache-2.0 (the
`LICENSE` file at the root).

### Apache License 2.0 — Google Wycheproof

The Apache License, Version 2.0, is the `LICENSE` file at the root of this
distribution.

### U.S. Government works

NIST ACVP and CAVP test data are works of the United States Government and
are not subject to copyright in the United States (17 U.S.C. §105).
