import ISO_8824
import ISO_8825
import Time_Primitive

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct Certificate {

    @inlinable
    public var version: Version {
        self.tbsCertificate.version
    }

    @inlinable
    public var serialNumber: SerialNumber {
        self.tbsCertificate.serialNumber
    }

    @inlinable
    public var publicKey: PublicKey {
        self.tbsCertificate.publicKey
    }

    @inlinable
    public var notValidBefore: Instant {
        Instant(self.tbsCertificate.validity.notBefore)
    }

    @inlinable
    public var notValidAfter: Instant {
        Instant(self.tbsCertificate.validity.notAfter)
    }

    @inlinable
    public var issuer: DistinguishedName {
        self.tbsCertificate.issuer
    }

    @inlinable
    public var subject: DistinguishedName {
        self.tbsCertificate.subject
    }

    @inlinable
    public var extensions: Extensions {
        self.tbsCertificate.extensions
    }

    @usableFromInline
    internal let tbsCertificate: TBSCertificate

    public let tbsCertificateBytes: ArraySlice<UInt8>

    public let signature: Signature

    public let signatureAlgorithm: SignatureAlgorithm

    @usableFromInline
    internal let signatureBytes: ArraySlice<UInt8>

    @usableFromInline
    internal let signatureAlgorithmBytes: ArraySlice<UInt8>

    @inlinable
    package init(
        tbsCertificate: TBSCertificate,
        signatureAlgorithm: AlgorithmIdentifier,
        signature: ISO_8824.BitString,
        tbsCertificateBytes: ArraySlice<UInt8>,
        signatureAlgorithmBytes: ArraySlice<UInt8>,
        signatureBytes: ArraySlice<UInt8>
    ) throws(ISO_8824.Error) {
        self.tbsCertificate = tbsCertificate
        self.signatureAlgorithm = SignatureAlgorithm(algorithmIdentifier: signatureAlgorithm)

        do {
            self.signature = try Signature(
                signatureAlgorithm: self.signatureAlgorithm,
                signatureBytes: signature
            )
        } catch {
            throw ISO_8824.Error.invalidASN1Object(reason: "\(error)")
        }
        self.tbsCertificateBytes = tbsCertificateBytes
        self.signatureAlgorithmBytes = signatureAlgorithmBytes
        self.signatureBytes = signatureBytes
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate: Hashable {
    @inlinable
    public static func == (lhs: Certificate, rhs: Certificate) -> Bool {
        return lhs.tbsCertificateBytes == rhs.tbsCertificateBytes
            && lhs.signatureBytes == rhs.signatureBytes
            && lhs.signatureAlgorithmBytes == rhs.signatureAlgorithmBytes
    }

    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.tbsCertificateBytes)
        hasher.combine(self.signatureBytes)
        hasher.combine(self.signatureAlgorithmBytes)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate: CustomStringConvertible {
    public var description: String {
        """
        Certificate(\
        version: \(String(reflecting: self.version)), \
        serialNumber: \(String(reflecting: self.serialNumber)), \
        issuer: \(String(reflecting: self.issuer)), \
        subject: \(String(reflecting: self.subject)), \
        notValidBefore: \(String(reflecting: self.notValidBefore)), \
        notValidAfter: \(String(reflecting: self.notValidAfter)), \
        publicKey: \(String(reflecting: self.publicKey)), \
        signature: \(String(reflecting: self.signature)), \
        extensions: \(String(reflecting: self.extensions))\
        )
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @inlinable
    public init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) {
            (
                nodes: inout ISO_8825.Node.Collection.Iterator
            ) throws(ISO_8824.Error)
                -> Certificate in
            guard let tbsCertificateNode = nodes.next(),
                let signatureAlgorithmNode = nodes.next(),
                let signatureNode = nodes.next()
            else {
                throw ISO_8824.Error.invalidASN1Object(
                    reason: "Invalid certificate object, insufficient ASN.1 nodes"
                )
            }
            let tbsCertificate = try TBSCertificate(derEncoded: tbsCertificateNode)
            let signatureAlgorithm = try AlgorithmIdentifier(derEncoded: signatureAlgorithmNode)
            let signature = try ISO_8824.BitString(derEncoded: signatureNode)
            return try Certificate(
                tbsCertificate: tbsCertificate,
                signatureAlgorithm: signatureAlgorithm,
                signature: signature,
                tbsCertificateBytes: tbsCertificateNode.encodedBytes,
                signatureAlgorithmBytes: signatureAlgorithmNode.encodedBytes,
                signatureBytes: signatureNode.encodedBytes
            )
        }
    }

    @inlinable
    public func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        coder.appendConstructedNode(identifier: identifier) { coder in
            coder.serializeRawBytes(self.tbsCertificateBytes)
            coder.serializeRawBytes(self.signatureAlgorithmBytes)
            coder.serializeRawBytes(self.signatureBytes)
        }
    }
}

extension ISO_8825.DER.Serializer {
    @inlinable
    package static func serialized<Element: ISO_8825.DER.Serializable>(
        element: Element
    ) throws(ISO_8824.Error) -> [UInt8] {
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(element)
        return serializer.serializedBytes
    }

}
