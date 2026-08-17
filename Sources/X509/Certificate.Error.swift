// ===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

import ISO_8824

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// A failure condition raised by the certificate model surfaces.
    ///
    /// Verification outcomes are not errors: policy rejection is reported through
    /// ``CertificateValidationResult`` and ``PolicyEvaluationResult``, never thrown.
    public enum Error: Swift.Error, Hashable, Sendable {
        /// An algorithm outside the supported verification surface.
        case algorithm(Algorithm)

        /// A signature whose encoded form is not acceptable.
        case signature(Signature)

        /// An extension whose OID usage is invalid.
        case `extension`(Extension)

        /// An ASN.1 encode or decode failure surfaced by a certificate-model operation.
        ///
        /// Decode-boundary bridge (N5 Option A), inverted: where a model surface owns the
        /// typed error and its body also performs DER work, the ASN.1 side routes through
        /// this leaf case, preserving the underlying ``ISO_8824/Error`` detail.
        case der(ISO_8824.Error)
    }
}
