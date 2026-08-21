import ISO_8824
import ISO_8825

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public struct Signature {
        @usableFromInline
        var backing: BackingSignature

        @inlinable
        internal init(backing: BackingSignature) {
            self.backing = backing
        }

        @inlinable
        public init(
            signatureAlgorithm: SignatureAlgorithm,
            signatureBytes: ISO_8824.BitString
        ) throws(Certificate.Error) {
            switch signatureAlgorithm {
            case .ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512:
                let signature: ECDSASignature
                do {
                    signature = try ECDSASignature(derEncoded: signatureBytes.bytes)
                } catch {
                    throw Certificate.Error.der(error)
                }
                self.backing = .ecdsa(signature)

            case .ed25519:
                guard signatureBytes.paddingBits == 0 else {
                    throw Certificate.Error.signature(
                        .invalidEncoding(
                            reason: "no padding bits are allowed on Ed25519 signatures"
                        )
                    )
                }
                self.backing = .ed25519(Array(signatureBytes.bytes))

            default:
                throw Certificate.Error.algorithm(
                    .unsupportedSignature(AlgorithmIdentifier(signatureAlgorithm).algorithm)
                )
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature: CustomStringConvertible {
    public var description: String {
        switch backing {
        case .ecdsa:
            return "ECDSA"

        case .ed25519:
            return "Ed25519"
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature {

    @usableFromInline
    enum BackingSignature: Hashable, Sendable {
        case ecdsa(ECDSASignature)
        case ed25519([UInt8])

        @inlinable
        static func == (lhs: BackingSignature, rhs: BackingSignature) -> Bool {
            switch (lhs, rhs) {
            case (.ecdsa(let l), .ecdsa(let r)):
                return l == r

            case (.ed25519(let l), .ed25519(let r)):
                return l == r

            default:
                return false
            }
        }

        @inlinable
        func hash(into hasher: inout Hasher) {
            switch self {
            case .ecdsa(let sig):
                hasher.combine(0)
                hasher.combine(sig)

            case .ed25519(let sig):
                hasher.combine(2)
                hasher.combine(sig)
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature {

    @inlinable
    public var rawRepresentation: [UInt8] {
        switch self.backing {
        case .ecdsa(let sig):
            var serializer = ISO_8825.DER.Serializer()

            try! serializer.serialize(sig)
            return serializer.serializedBytes

        case .ed25519(let bytes):
            return bytes
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ISO_8824.BitString {
    @inlinable
    package init(_ signature: Certificate.Signature) throws(ISO_8824.Error) {
        try self.init(bytes: signature.rawRepresentation[...])
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ISO_8824.OctetString {
    @inlinable
    package init(_ signature: Certificate.Signature) {
        switch signature.backing {
        case .ecdsa(let sig):
            var serializer = ISO_8825.DER.Serializer()

            try! serializer.serialize(sig)
            self = ISO_8824.OctetString(contentBytes: serializer.serializedBytes[...])

        case .ed25519(let sig):
            self = ISO_8824.OctetString(contentBytes: sig[...])
        }
    }
}
