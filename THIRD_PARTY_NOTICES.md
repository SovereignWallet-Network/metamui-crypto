# Third-party notices for MetaMUI Crypto (Rust preview)

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

### Apache License 2.0 — Google Wycheproof

The Apache License, Version 2.0, is the `LICENSE` file at the root of this
distribution.

### U.S. Government works

NIST ACVP and CAVP test data are works of the United States Government and
are not subject to copyright in the United States (17 U.S.C. §105).
