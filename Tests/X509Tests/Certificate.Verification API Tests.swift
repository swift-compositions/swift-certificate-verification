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

import Testing
import ISO_8824
@testable import Certificates

private struct CanonicalPolicy: Certificate.Policy {
    var verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] = []

    mutating func chainMeetsPolicyRequirements(
        chain: Certificate.Chain.Unverified
    ) async -> Certificate.Policy.Result {
        .meetsPolicy
    }
}

extension Certificate {
    @Suite struct `Verification API` {}
}

extension Certificate.`Verification API` {
    @Test func `canonical verification names preserve established types`() {
        let verifier: Certificate.Verifier<CanonicalPolicy>.Type = Verifier<CanonicalPolicy>.self
        let chain: Certificate.Chain.Type = ValidatedCertificateChain.self
        let hostname: Certificate.Hostname.Type = ServerIdentityPolicy.self
        let verification: Certificate.Verification.Type = CertificateValidationResult.self
        let policy: Certificate.Policy.Result.Type = PolicyEvaluationResult.self
        let failure: Certificate.Policy.Failure.Type = PolicyFailureReason.self
        let result: Certificate.Verifier<CanonicalPolicy>.Result.Type = CertificateValidationResult.self
        let policyFailure: Certificate.Verification.Failure.Type = CertificateValidationResult.PolicyFailure.self

        _ = (verifier, chain, hostname, verification, policy, failure, result, policyFailure)
    }
}
