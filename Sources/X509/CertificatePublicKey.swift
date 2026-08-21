import ISO_8824
import ISO_8825

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public struct PublicKey {
        @usableFromInline
        var backing: BackingPublicKey

        @inlinable
        package init(spki: SubjectPublicKeyInfo) throws(Certificate.Error) {
            switch spki.algorithmIdentifier {
            case .p256PublicKey:
                guard spki.key.bytes.count == Certificate.PublicKey.p256X963ByteCount else {
                    throw Certificate.Error.algorithm(
                        .unsupportedPublicKey(spki.algorithmIdentifier.algorithm)
                    )
                }
                self.backing = .p256(x963: Array(spki.key.bytes))

            case .p384PublicKey:
                guard spki.key.bytes.count == Certificate.PublicKey.p384X963ByteCount else {
                    throw Certificate.Error.algorithm(
                        .unsupportedPublicKey(spki.algorithmIdentifier.algorithm)
                    )
                }
                self.backing = .p384(x963: Array(spki.key.bytes))

            case .p521PublicKey:
                guard spki.key.bytes.count == Certificate.PublicKey.p521X963ByteCount else {
                    throw Certificate.Error.algorithm(
                        .unsupportedPublicKey(spki.algorithmIdentifier.algorithm)
                    )
                }
                self.backing = .p521(x963: Array(spki.key.bytes))

            case .ed25519:
                guard spki.key.bytes.count == Certificate.PublicKey.ed25519RawByteCount else {
                    throw Certificate.Error.algorithm(
                        .unsupportedPublicKey(spki.algorithmIdentifier.algorithm)
                    )
                }
                self.backing = .ed25519(raw: Array(spki.key.bytes))

            default:
                throw Certificate.Error.algorithm(
                    .unsupportedPublicKey(spki.algorithmIdentifier.algorithm)
                )
            }
        }

        @inlinable
        internal init(backing: BackingPublicKey) {
            self.backing = backing
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {

    @usableFromInline
    static let p256X963ByteCount = 1 + 32 + 32

    @usableFromInline
    static let p384X963ByteCount = 1 + 48 + 48

    @usableFromInline
    static let p521X963ByteCount = 1 + 66 + 66

    @usableFromInline
    static let ed25519RawByteCount = 32
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: CustomStringConvertible {
    public var description: String {
        switch self.backing {
        case .p256:
            return "P256.PublicKey"

        case .p384:
            return "P384.PublicKey"

        case .p521:
            return "P521.PublicKey"

        case .ed25519:
            return "Ed25519.PublicKey"
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {

    @usableFromInline
    enum BackingPublicKey: Hashable, Sendable {
        case p256(x963: [UInt8])
        case p384(x963: [UInt8])
        case p521(x963: [UInt8])
        case ed25519(raw: [UInt8])
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SubjectPublicKeyInfo {
    @inlinable
    package init(_ publicKey: Certificate.PublicKey) throws(ISO_8824.Error) {
        let algorithmIdentifier: AlgorithmIdentifier
        let key: ISO_8824.BitString

        switch publicKey.backing {
        case .p256(let bytes):
            algorithmIdentifier = .p256PublicKey
            key = try .init(bytes: bytes[...])

        case .p384(let bytes):
            algorithmIdentifier = .p384PublicKey
            key = try .init(bytes: bytes[...])

        case .p521(let bytes):
            algorithmIdentifier = .p521PublicKey
            key = try .init(bytes: bytes[...])

        case .ed25519(let bytes):
            algorithmIdentifier = .ed25519
            key = try .init(bytes: bytes[...])
        }

        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {

    @inlinable
    public var subjectPublicKeyInfoBytes: ArraySlice<UInt8> {
        switch self.backing {
        case .p256(let bytes), .p384(let bytes), .p521(let bytes), .ed25519(let bytes):
            return bytes[...]
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        SubjectPublicKeyInfo.defaultIdentifier
    }

    @inlinable
    public init(
        derEncoded: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        let spki = try SubjectPublicKeyInfo(derEncoded: derEncoded, withIdentifier: identifier)

        do {
            try self.init(spki: spki)
        } catch {
            throw ISO_8824.Error.invalidASN1Object(reason: "\(error)")
        }
    }

    @inlinable
    public func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        let spki = try SubjectPublicKeyInfo(self)
        try spki.serialize(into: &coder, withIdentifier: identifier)
    }
}
