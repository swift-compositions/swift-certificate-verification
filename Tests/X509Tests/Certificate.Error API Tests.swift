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

import ISO_8824
import Testing
import Certificates

extension Certificate.Error {
    @Suite struct API {
        @Suite struct Unit {}
    }
}

extension Certificate.Error.API.Unit {
    @Test func `public model and extension operations retain their typed failures`() {
        let _: ([RelativeDistinguishedName.Attribute]) -> DistinguishedName = DistinguishedName.init
        let _: (String) throws(ISO_8824.Error) -> RelativeDistinguishedName.Attribute.Value = {
            try .init(printableString: $0)
        }
        let _: (ISO_8824.ObjectIdentifier, String) throws(ISO_8824.Error) -> RelativeDistinguishedName.Attribute = {
            try .init(type: $0, ia5String: $1)
        }
        let _: ([Certificate.Extension]) throws(Certificate.Error) -> Certificate.Extensions = {
            try .init($0)
        }
        let _: ([ExtendedKeyUsage.Usage]) throws(Certificate.Error) -> ExtendedKeyUsage = {
            try .init($0)
        }
        let _: (Certificate.SignatureAlgorithm, ISO_8824.BitString) throws(Certificate.Error) -> Certificate.Signature = {
            try .init(signatureAlgorithm: $0, signatureBytes: $1)
        }

        let _: (Certificate.Extension) throws(Certificate.Error) -> AuthorityInformationAccess = AuthorityInformationAccess.init
        let _: (Certificate.Extension) throws(Certificate.Error) -> AuthorityKeyIdentifier = AuthorityKeyIdentifier.init
        let _: (Certificate.Extension) throws(Certificate.Error) -> BasicConstraints = BasicConstraints.init
        let _: (Certificate.Extension) throws(Certificate.Error) -> ExtendedKeyUsage = ExtendedKeyUsage.init
        let _: (Certificate.Extension) throws(Certificate.Error) -> KeyUsage = KeyUsage.init
        let _: (Certificate.Extension) throws(Certificate.Error) -> NameConstraints = NameConstraints.init
        let _: (Certificate.Extension) throws(Certificate.Error) -> SubjectAlternativeNames = SubjectAlternativeNames.init
        let _: (Certificate.Extension) throws(Certificate.Error) -> SubjectKeyIdentifier = SubjectKeyIdentifier.init

        let _: (AuthorityInformationAccess, Bool) throws(ISO_8824.Error) -> Certificate.Extension = Certificate.Extension.init
        let _: (AuthorityKeyIdentifier, Bool) throws(ISO_8824.Error) -> Certificate.Extension = Certificate.Extension.init
        let _: (BasicConstraints, Bool) throws(ISO_8824.Error) -> Certificate.Extension = Certificate.Extension.init
        let _: (ExtendedKeyUsage, Bool) throws(ISO_8824.Error) -> Certificate.Extension = Certificate.Extension.init
        let _: (KeyUsage, Bool) throws(ISO_8824.Error) -> Certificate.Extension = Certificate.Extension.init
        let _: (NameConstraints, Bool) throws(ISO_8824.Error) -> Certificate.Extension = Certificate.Extension.init
        let _: (SubjectAlternativeNames, Bool) throws(ISO_8824.Error) -> Certificate.Extension = Certificate.Extension.init
        let _: (SubjectKeyIdentifier, Bool) throws(ISO_8824.Error) -> Certificate.Extension = Certificate.Extension.init

        let _: (Certificate.Extensions) throws(Certificate.Error) -> AuthorityInformationAccess? = {
            try $0.authorityInformationAccess
        }
        let _: (Certificate.Extensions) throws(Certificate.Error) -> SubjectKeyIdentifier? = {
            try $0.subjectKeyIdentifier
        }
        let _: (Certificate.Extensions) throws(Certificate.Error) -> AuthorityKeyIdentifier? = {
            try $0.authorityKeyIdentifier
        }
        let _: (Certificate.Extensions) throws(Certificate.Error) -> ExtendedKeyUsage? = {
            try $0.extendedKeyUsage
        }
        let _: (Certificate.Extensions) throws(Certificate.Error) -> BasicConstraints? = {
            try $0.basicConstraints
        }
        let _: (Certificate.Extensions) throws(Certificate.Error) -> KeyUsage? = {
            try $0.keyUsage
        }
        let _: (Certificate.Extensions) throws(Certificate.Error) -> NameConstraints? = {
            try $0.nameConstraints
        }
        let _: (Certificate.Extensions) throws(Certificate.Error) -> SubjectAlternativeNames? = {
            try $0.subjectAlternativeNames
        }
    }

    @Test func `certificate error taxonomy remains exhaustively typed`() {
        func classify(_ error: Certificate.Error) -> Int {
            switch error {
            case .algorithm: 0
            case .signature: 1
            case .extension: 2
            case .asn1: 3
            }
        }

        #expect(classify(.asn1(.invalidASN1Object)) == 3)
    }
}
