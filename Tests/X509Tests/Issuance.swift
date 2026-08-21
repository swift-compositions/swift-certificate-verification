@preconcurrency import Crypto
import ISO_8824
import ISO_8825
import Time_Primitive

@testable import Certificates

extension Certificate {

    enum Issuance {}
}

extension Certificate.Issuance {

    struct Key {
        enum Backing {
            case p256(P256.Signing.PrivateKey)
            case p384(P384.Signing.PrivateKey)
            case p521(P521.Signing.PrivateKey)
            case ed25519(Curve25519.Signing.PrivateKey)
        }

        var backing: Backing

        init(_ key: P256.Signing.PrivateKey) { self.backing = .p256(key) }
        init(_ key: P384.Signing.PrivateKey) { self.backing = .p384(key) }
        init(_ key: P521.Signing.PrivateKey) { self.backing = .p521(key) }
        init(_ key: Curve25519.Signing.PrivateKey) { self.backing = .ed25519(key) }

        var publicKey: Certificate.PublicKey {
            switch self.backing {
            case .p256(let key): return Certificate.PublicKey(key.publicKey)
            case .p384(let key): return Certificate.PublicKey(key.publicKey)
            case .p521(let key): return Certificate.PublicKey(key.publicKey)
            case .ed25519(let key): return Certificate.PublicKey(key.publicKey)
            }
        }

        func signature(
            for bytes: [UInt8],
            algorithm: Certificate.SignatureAlgorithm
        ) throws -> [UInt8] {
            switch (self.backing, algorithm) {
            case (.p256(let key), .ecdsaWithSHA256):
                return Array(try key.signature(for: SHA256.hash(data: bytes)).derRepresentation)

            case (.p256(let key), .ecdsaWithSHA384):
                return Array(try key.signature(for: SHA384.hash(data: bytes)).derRepresentation)

            case (.p256(let key), .ecdsaWithSHA512):
                return Array(try key.signature(for: SHA512.hash(data: bytes)).derRepresentation)

            case (.p384(let key), .ecdsaWithSHA256):
                return Array(try key.signature(for: SHA256.hash(data: bytes)).derRepresentation)

            case (.p384(let key), .ecdsaWithSHA384):
                return Array(try key.signature(for: SHA384.hash(data: bytes)).derRepresentation)

            case (.p384(let key), .ecdsaWithSHA512):
                return Array(try key.signature(for: SHA512.hash(data: bytes)).derRepresentation)

            case (.p521(let key), .ecdsaWithSHA256):
                return Array(try key.signature(for: SHA256.hash(data: bytes)).derRepresentation)

            case (.p521(let key), .ecdsaWithSHA384):
                return Array(try key.signature(for: SHA384.hash(data: bytes)).derRepresentation)

            case (.p521(let key), .ecdsaWithSHA512):
                return Array(try key.signature(for: SHA512.hash(data: bytes)).derRepresentation)

            case (.ed25519(let key), .ed25519):
                return Array(try key.signature(for: bytes))

            default:
                throw Failure.keyDoesNotSupportAlgorithm
            }
        }
    }

    enum Failure: Swift.Error {

        case keyDoesNotSupportAlgorithm
    }
}

extension Certificate.Issuance {

    static func issue(
        version: Certificate.Version = .v3,
        serialNumber: Certificate.SerialNumber,
        publicKey: Certificate.PublicKey,
        notValidBefore: Instant,
        notValidAfter: Instant,
        issuer: DistinguishedName,
        subject: DistinguishedName,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        extensions: Certificate.Extensions,
        issuerPrivateKey: Key
    ) throws -> Certificate {

        let validity = Validity(
            notBefore: try Time.makeTime(from: notValidBefore),
            notAfter: try Time.makeTime(from: notValidAfter)
        )

        let tbsCertificate = TBSCertificate(
            version: version,
            serialNumber: serialNumber,
            signature: signatureAlgorithm,
            issuer: issuer,
            validity: validity,
            subject: subject,
            publicKey: publicKey,
            extensions: extensions
        )

        let tbsCertificateBytes = try ISO_8825.DER.Serializer.serialized(element: tbsCertificate)
        let signatureBytes = try issuerPrivateKey.signature(
            for: tbsCertificateBytes,
            algorithm: signatureAlgorithm
        )

        var coder = ISO_8825.DER.Serializer()
        try coder.appendConstructedNode(identifier: .sequence) { coder in

            coder.serializeRawBytes(tbsCertificateBytes[...])
            try coder.serialize(AlgorithmIdentifier(signatureAlgorithm))
            try coder.serialize(ISO_8824.BitString(bytes: signatureBytes[...]))
        }

        return try Certificate(derEncoded: coder.serializedBytes)
    }
}
