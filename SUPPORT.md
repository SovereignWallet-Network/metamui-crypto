# Support and version policy

## Level of support

MetaMUI Crypto is a **prerelease**. Support is best effort: maintainers
answer issues and review pull requests as capacity allows, there is no
service-level agreement, no long-term-support line, and no guaranteed
response time. Commercial support is not offered through this repository.

That sentence is the whole promise. What follows says how to tell a
maintained commitment from a best-effort one.

## What "supported" means

The support table published with each release (generated from the release
catalog; nothing is written into it by hand) marks every
profile × target cell as one of:

| mark | meaning |
|---|---|
| validated | implemented on that target and verified against the algorithm's upstream test vectors through the public API |
| implemented | present in the tree, validation not yet run or not passing — evaluation only |
| experimental | shipped for evaluation; may change or be removed without a deprecation period |
| not available | not implemented on that target, or the parameter set was dropped by its upstream |

Only *validated* cells are covered by the security policy and by the
compatibility rules below. A claim that does not appear in the table is not
a claim this project makes. Internal review, independent audit and formal
certification are recorded separately and are never implied by a
*validated* mark.

This tree is the Rust source of the preview: the `falcon-512.r3-compressed`,
`falcon-512.r3-padded` and `ml-kem-768` profiles through the
`metamui-crypto` facade, validated on macOS (arm64) and Linux (x86_64). No
package has been published to a registry from it.

## Versions

- The workspace carries one version across every crate (`Cargo.toml`
  `[workspace.package]`), following semantic versioning; a release of the
  whole project carries that version.
- **Minor** releases may add profiles, targets and APIs. **Major** releases
  may remove them, after at least one minor release in which the removal is
  documented as deprecated.
- **Patch** releases fix bugs and security issues without changing any wire
  byte of a validated profile.
- Fixes land on the latest release line. During the prerelease period there
  are no backports to earlier lines.

## Wire compatibility

A profile identifier (for example `falcon-512.r3-padded`, `ml-kem-768`)
names one algorithm, one parameter set and one byte encoding, and its
meaning never changes. If any byte of a key, signature, ciphertext or header
changes, or the way randomness is consumed changes, the result is a new
profile with a new identifier; the old one keeps verifying what it verified.
Cross-version rules for revised algorithms (for example Round-3 Falcon and
the eventual FN-DSA standard) are stated per profile in the release notes
and are never silent.

Breaking changes to APIs are listed under a **Breaking** heading in the
release notes of the release that makes them, with the migration.

## Standards and errata

The maintainers track the standards the validated profiles implement (FIPS
203, FIPS 202, SP 800-185, SP 800-38D, SP 800-90A and the Falcon Round-3
specification) and their errata. A revision that changes bytes produces a
new profile; a revision that does not is noted in the release notes.

## Where to ask

- Usage questions and bugs: GitHub issues on this repository. Pull requests
  are welcome; see `CONTRIBUTING.md`.
- Security: **security@metamui.id** — never a public issue (`SECURITY.md`).
- Ownership: each algorithm area and the release process has a maintainer of
  record listed in the release notes of each release.
