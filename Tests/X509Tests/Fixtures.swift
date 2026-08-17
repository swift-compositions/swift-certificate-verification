//===----------------------------------------------------------------------===//
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
//===----------------------------------------------------------------------===//

import Byte_Primitive
import Testing
@testable import Certificates

/// Loads the frozen DER fixture corpus (N5 gate scenarios) embedded in
/// `Fixture.Documents`. Slice-1 tests bind pre-generated certificates rather than
/// issuing them in-test (issuance is an excluded surface — see the fixture
/// MANIFEST and the deferred-tests ledger).
enum Fixture {
    /// The raw DER bytes of a frozen fixture (e.g. `.der("leaf-valid")`).
    static func der(_ name: String) throws -> [UInt8] {
        let document = try #require(
            Documents[name],
            "missing frozen fixture: \(name)"
        )
        return document.map(\.underlying)
    }

    /// A frozen fixture parsed into a `Certificate`.
    static func certificate(_ name: String) throws -> Certificate {
        try Certificate(derEncoded: try der(name))
    }
}
