# Security Policy

## Reporting a vulnerability

Please do not report security problems in public issues or pull requests.

Send reports to **security@metamui.id**. Include the affected profile
(algorithm, parameter set, encoding), crate and version, a description, and
reproduction steps or a proof of concept. You will receive an
acknowledgement within five business days. If you do not, resend the
report; do not escalate to a public channel until 90 days after your first
message.

Encrypted reports: a PGP key for the address above will be published in this
file before the first public release. Until then, ask for one in a plain
first message and the response will carry it.

## What happens next

1. **Triage** — a maintainer reproduces the report and assigns a severity
   (Critical / High / Medium / Low) based on the affected profiles and the
   attack model.
2. **Fix** — developed in the source repository, verified against the
   upstream known-answer vectors and the regression test added for the
   finding, then exported here. Target: Critical and High within 30 days of
   triage; others in the next planned release. These are targets, not
   commitments — this is a best-effort prerelease project (see `SUPPORT.md`).
3. **Advisory** — published with the fixed release as a GitHub security
   advisory on this repository, in the format below. Reporters are credited
   unless they ask not to be.
4. **Disclosure** — coordinated with the reporter; the advisory is published
   no later than the fix, and no earlier than the fix unless the issue is
   already public.

## Advisory format

Every advisory states: the affected **profiles** and crates, the affected
version range, the fixed version, whether keys, signatures or ciphertexts
produced by affected versions need re-issue, and the CVE/GHSA identifier
once assigned.

## Scope and limits

Only what the support table (`SUPPORT.md`) lists as *validated* is in scope
for a security fix; *experimental* and *not validated* cells are shipped for
evaluation and carry no fix commitment. Things this project does not claim,
and reports about which will be triaged as hardening requests rather than
vulnerabilities:

- Measured timing or power side-channel resistance. The Rust cores are
  written with constant-time idioms for secret-dependent selection and
  comparison; no measurement has been made on any target.
- Behaviour of algorithms marked evaluation-only, of feature-gated draft
  hooks (`fn-dsa-draft`), and of parameter sets dropped by their upstream
  specification.
- Physical fault injection and hardware attacks.

Conformance to upstream test vectors, this project's internal review and an
independent audit are three different things. Passing vectors does not
mean audited; no independent audit has been performed on this tree.

## Supported versions for fixes

Fixes are made on the latest release line only. Older releases receive no
backports during the prerelease period.
