//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// A verifier that builds certificate chains and evaluates a declared policy.
    ///
    /// This is the canonical certificate-verification entry point. It forwards to
    /// ``Verifier`` so the established global spelling remains source-compatible.
    public typealias Verifier<Policy: VerifierPolicy> = Certificates.Verifier<Policy>

    /// A validated certificate chain, ordered from leaf to trust anchor.
    ///
    /// ``Chain/Unverified`` is the policy-input counterpart used while the
    /// verifier evaluates candidate chains.
    public typealias Chain = ValidatedCertificateChain

    /// A policy that validates the hostname or IP identity of a certificate.
    ///
    /// This is the canonical spelling of ``ServerIdentityPolicy``. It validates
    /// certificate identity only; TLS protocol and transport state stay outside
    /// this package.
    public typealias Hostname = ServerIdentityPolicy

    /// The policy contract used by a ``Certificate/Verifier``.
    public typealias Policy = VerifierPolicy

    /// The result of certificate-chain validation.
    public typealias Verification = CertificateValidationResult
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Verifier {
    /// The result returned by ``validate(leaf:intermediates:diagnosticCallback:)``.
    public typealias Result = CertificateValidationResult
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ValidatedCertificateChain {
    /// A chain that is being considered by a ``Certificate/Policy``.
    public typealias Unverified = UnverifiedCertificateChain
}

extension VerifierPolicy {
    /// The outcome of evaluating this policy against a candidate chain.
    public typealias Result = PolicyEvaluationResult

    /// The reason a policy did not accept a candidate chain.
    public typealias Failure = PolicyFailureReason
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateValidationResult {
    /// A policy failure collected while no candidate chain could be validated.
    public typealias Failure = PolicyFailure
}
