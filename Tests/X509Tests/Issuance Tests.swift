@preconcurrency import Crypto
import ISO_8824
import ISO_8825
import Testing
import Time_Primitive

@testable import Certificates

extension Certificate.Issuance {
    @Suite struct Test {
        @Suite struct Unit {}
        @Suite struct Integration {}
    }
}

extension Certificate.Issuance.Test {

    static let now = Instant(secondsSinceUnixEpoch: 1_767_225_600)
    static let aYearEarlier = Instant(secondsSinceUnixEpoch: 1_735_689_600)
    static let aDecadeLater = Instant(secondsSinceUnixEpoch: 2_051_222_400)

    static func name(_ commonName: String) throws -> DistinguishedName {
        try DistinguishedName([
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.commonName,
                utf8String: commonName
            )
        ])
    }

    static func certificateAuthority() throws -> Certificate.Extensions {
        try Certificate.Extensions([
            Certificate.Extension(
                BasicConstraints.isCertificateAuthority(maxPathLength: nil),
                critical: true
            )
        ])
    }

    static func endEntity() throws -> Certificate.Extensions {
        try Certificate.Extensions([
            Certificate.Extension(BasicConstraints.notCertificateAuthority, critical: true)
        ])
    }
}

extension Certificate.Issuance.Test.Unit {
    typealias Fixtures = Certificate.Issuance.Test

    @Test func `an issued self-signed certificate verifies under its own key`() throws {
        let key = Certificate.Issuance.Key(P256.Signing.PrivateKey())
        let name = try Fixtures.name("Issuance Test Root")

        let root = try Certificate.Issuance.issue(
            serialNumber: Certificate.SerialNumber(1),
            publicKey: key.publicKey,
            notValidBefore: Fixtures.aYearEarlier,
            notValidAfter: Fixtures.aDecadeLater,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Fixtures.certificateAuthority(),
            issuerPrivateKey: key
        )

        #expect(root.subject == name)
        #expect(root.issuer == name)
        #expect(root.publicKey == key.publicKey)
        #expect(
            Certificate.Verify.crypto.signature(
                root.signatureAlgorithm,
                root.publicKey,
                root.signature,
                root.tbsCertificateBytes
            )
        )
    }

    @Test func `an issued certificate does not verify under an unrelated key`() throws {
        let key = Certificate.Issuance.Key(P256.Signing.PrivateKey())
        let stranger = Certificate.Issuance.Key(P256.Signing.PrivateKey())
        let name = try Fixtures.name("Issuance Test Root")

        let root = try Certificate.Issuance.issue(
            serialNumber: Certificate.SerialNumber(2),
            publicKey: key.publicKey,
            notValidBefore: Fixtures.aYearEarlier,
            notValidAfter: Fixtures.aDecadeLater,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Fixtures.certificateAuthority(),
            issuerPrivateKey: key
        )

        #expect(
            !Certificate.Verify.crypto.signature(
                root.signatureAlgorithm,
                stranger.publicKey,
                root.signature,
                root.tbsCertificateBytes
            )
        )
    }

    @Test func `every supported key and algorithm pairing issues and verifies`() throws {
        let pairings: [(Certificate.Issuance.Key, Certificate.SignatureAlgorithm)] = [
            (.init(P256.Signing.PrivateKey()), .ecdsaWithSHA256),
            (.init(P256.Signing.PrivateKey()), .ecdsaWithSHA384),
            (.init(P384.Signing.PrivateKey()), .ecdsaWithSHA384),
            (.init(P521.Signing.PrivateKey()), .ecdsaWithSHA512),
            (.init(Curve25519.Signing.PrivateKey()), .ed25519),
        ]

        for (key, algorithm) in pairings {
            let name = try Fixtures.name("Issuance Test \(algorithm)")
            let certificate = try Certificate.Issuance.issue(
                serialNumber: Certificate.SerialNumber(3),
                publicKey: key.publicKey,
                notValidBefore: Fixtures.aYearEarlier,
                notValidAfter: Fixtures.aDecadeLater,
                issuer: name,
                subject: name,
                signatureAlgorithm: algorithm,
                extensions: try Fixtures.certificateAuthority(),
                issuerPrivateKey: key
            )

            #expect(
                Certificate.Verify.crypto.signature(
                    certificate.signatureAlgorithm,
                    certificate.publicKey,
                    certificate.signature,
                    certificate.tbsCertificateBytes
                ),
                "\(algorithm) issued a signature its own witness rejects"
            )
        }
    }

    @Test func `a key that cannot sign under the algorithm is refused`() throws {
        let ed25519 = Certificate.Issuance.Key(Curve25519.Signing.PrivateKey())
        let name = try Fixtures.name("Issuance Test Mismatch")

        #expect(throws: Certificate.Issuance.Failure.keyDoesNotSupportAlgorithm) {
            try Certificate.Issuance.issue(
                serialNumber: Certificate.SerialNumber(4),
                publicKey: ed25519.publicKey,
                notValidBefore: Fixtures.aYearEarlier,
                notValidAfter: Fixtures.aDecadeLater,
                issuer: name,
                subject: name,
                signatureAlgorithm: .ecdsaWithSHA256,
                extensions: try Fixtures.certificateAuthority(),
                issuerPrivateKey: ed25519
            )
        }
    }
}

extension Certificate.Issuance.Test.Integration {
    typealias Fixtures = Certificate.Issuance.Test

    @Test func `a chain issued by this seam validates through the real verifier`() async throws {
        let rootKey = Certificate.Issuance.Key(P384.Signing.PrivateKey())
        let rootName = try Fixtures.name("Issuance Test Root CA")
        let root = try Certificate.Issuance.issue(
            serialNumber: Certificate.SerialNumber(10),
            publicKey: rootKey.publicKey,
            notValidBefore: Fixtures.aYearEarlier,
            notValidAfter: Fixtures.aDecadeLater,
            issuer: rootName,
            subject: rootName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try Fixtures.certificateAuthority(),
            issuerPrivateKey: rootKey
        )

        let leafKey = Certificate.Issuance.Key(P256.Signing.PrivateKey())
        let leafName = try Fixtures.name("Issuance Test Leaf")
        let leaf = try Certificate.Issuance.issue(
            serialNumber: Certificate.SerialNumber(11),
            publicKey: leafKey.publicKey,
            notValidBefore: Fixtures.aYearEarlier,
            notValidAfter: Fixtures.aDecadeLater,
            issuer: rootName,
            subject: leafName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Fixtures.endEntity(),
            issuerPrivateKey: rootKey
        )

        var verifier = Verifier(
            rootCertificates: CertificateStore([root]),
            verify: .crypto
        ) {
            RFC5280Policy(validationTime: Fixtures.now)
        }

        let result = await verifier.validate(leaf: leaf, intermediates: CertificateStore())

        guard case .validCertificate(let chain) = result else {
            Issue.record("issued chain failed to validate: \(result)")
            return
        }
        #expect(Array(chain) == [leaf, root])
    }

    @Test func `a chain whose leaf was signed by a stranger does not validate`() async throws {
        let rootKey = Certificate.Issuance.Key(P384.Signing.PrivateKey())
        let rootName = try Fixtures.name("Issuance Test Root CA")
        let root = try Certificate.Issuance.issue(
            serialNumber: Certificate.SerialNumber(20),
            publicKey: rootKey.publicKey,
            notValidBefore: Fixtures.aYearEarlier,
            notValidAfter: Fixtures.aDecadeLater,
            issuer: rootName,
            subject: rootName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try Fixtures.certificateAuthority(),
            issuerPrivateKey: rootKey
        )

        let leafKey = Certificate.Issuance.Key(P256.Signing.PrivateKey())
        let leafName = try Fixtures.name("Issuance Test Leaf")
        let stranger = Certificate.Issuance.Key(P384.Signing.PrivateKey())

        func leaf(signedBy issuerKey: Certificate.Issuance.Key) throws -> Certificate {
            try Certificate.Issuance.issue(
                serialNumber: Certificate.SerialNumber(21),
                publicKey: leafKey.publicKey,
                notValidBefore: Fixtures.aYearEarlier,
                notValidAfter: Fixtures.aDecadeLater,
                issuer: rootName,
                subject: leafName,
                signatureAlgorithm: .ecdsaWithSHA384,
                extensions: try Fixtures.endEntity(),
                issuerPrivateKey: issuerKey
            )
        }

        var verifier = Verifier(
            rootCertificates: CertificateStore([root]),
            verify: .crypto
        ) {
            RFC5280Policy(validationTime: Fixtures.now)
        }

        let genuine = await verifier.validate(
            leaf: try leaf(signedBy: rootKey),
            intermediates: CertificateStore()
        )
        guard case .validCertificate = genuine else {
            Issue.record("control failed: the genuinely-signed leaf did not validate: \(genuine)")
            return
        }

        let impostor = await verifier.validate(
            leaf: try leaf(signedBy: stranger),
            intermediates: CertificateStore()
        )
        guard case .couldNotValidate = impostor else {
            Issue.record("a chain signed by an unrelated key validated: \(impostor)")
            return
        }
    }
}
