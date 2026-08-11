# swift-certificates-n5

![Development Status](https://img.shields.io/badge/status-work--in--progress-orange.svg)

Work-in-progress Institute adaptation of Apple's X.509 certificates library: the
chain-verification essence, with cryptography injected rather than linked.

> Forked from [apple/swift-certificates](https://github.com/apple/swift-certificates)
> at `24ccdee` (1.18.0). The upstream history remains reachable below the fork
> point; every retained source file keeps its upstream Apache-2.0 header, and
> `NOTICE.txt` names the SwiftCertificates project.

**This is not the publication tree.** The canonical `swift-certificates` name is
deliberately vacated while the wider Swift ecosystem resolves
`apple/swift-certificates` under that package identity; publication under a
permanent name is a separate, deliberate step.

---

## What this tree is

The `Certificates` library target carries the X.509 model and chain verifier,
reshaped against Institute conventions:

- **Crypto-free, Foundation-free main target.** Signature verification enters
  through an injected `Certificate.Verify` witness (algorithm + raw bytes);
  the Crypto-backed test witness lives in the nested test package, keeping
  `swift-crypto` and its transitive dependencies outside the production
  package's resolution closure.
- **Institute standards owners replace bundled implementations.** ASN.1 via
  ISO 8824/8825, IP addresses via RFC 791/4291, URI parsing via RFC 3986 —
  in place of vendored ASN.1, `inet_pton`, and `Foundation.URL`.
- **Injected verification time.** `Instant` replaces `Foundation.Date`; the
  verifier never reads a system clock.
- **Typed errors.** Every public throwing model and extension operation names
  its failure type. Model validation and extension decoding use the exhaustive
  `Certificate.Error` taxonomy; ASN.1 serialization uses `ISO_8824.Error`, the
  wire-format owner's error currency. Callback-polymorphic collection
  operations and policy-builder entry points preserve the callback's concrete
  failure type.

### Certificate-verification API

Certificate verification is exposed from its owner under the canonical
`Certificate` vocabulary:

- `Certificate.Verifier<Policy>` builds candidate chains and evaluates a policy.
- `Certificate.Chain` is the validated leaf-to-root result; its
  `Certificate.Chain.Unverified` counterpart is provided to policies during
  evaluation.
- `Certificate.Hostname` validates the certificate identity for a hostname or
  IP address.
- `Certificate.Policy`, `Certificate.Policy.Result`,
  `Certificate.Policy.Failure`, `Certificate.Verification`, and
  `Certificate.Verification.Failure` describe policy and validation outcomes.

These names are additive aliases of the established verification capability.
The original `Verifier`, `ValidatedCertificateChain`, `ServerIdentityPolicy`,
`VerifierPolicy`, and result spellings remain available for source
compatibility. This package does not implement TLS state, transport, or a
cryptographic backend; callers supply the existing `Certificate.Verify` witness.

Excluded surfaces — issuance and private keys, CSR, CMS, OCSP, PEM,
RSA/SecKey/SecureEnclave backends, system trust stores — were deleted at the
fork point and are deferred to dedicated future packages, not silently dropped:
git history preserves all of it, and each deferred test names the surface it
needs.

## Test posture

The root package retains the `Certificate Internals Tests`, while
`Tests/Package.swift` owns the Crypto-backed `Certificates Tests`. A further
tier of upstream test files remains excluded from the nested test target
pending the TestPKI restoration tracked by
[PR #8](https://github.com/swift-foundations/swift-certificate-verification/pull/8);
the exclusions are recorded per case in the fork's deferral ledger.

## License

Apache 2.0, unchanged from upstream — see `LICENSE.txt` and `NOTICE.txt`.
