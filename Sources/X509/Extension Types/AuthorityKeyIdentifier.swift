import ISO_8824
import ISO_8825
import Standard_Library_Extensions

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct AuthorityKeyIdentifier {

    public var keyIdentifier: ArraySlice<UInt8>?

    public var authorityCertIssuer: [GeneralName]?

    public var authorityCertSerialNumber: Certificate.SerialNumber?

    @inlinable
    public init(
        keyIdentifier: ArraySlice<UInt8>? = nil,
        authorityCertIssuer: [GeneralName]? = nil,
        authorityCertSerialNumber: Certificate.SerialNumber? = nil
    ) {
        self.keyIdentifier = keyIdentifier
        self.authorityCertIssuer = authorityCertIssuer
        self.authorityCertSerialNumber = authorityCertSerialNumber
    }

    @inlinable
    public init(_ ext: Certificate.Extension) throws(Certificate.Error) {
        guard ext.oid == .X509ExtensionID.authorityKeyIdentifier else {
            throw Certificate.Error.extension(
                .incorrectOID(expected: .X509ExtensionID.authorityKeyIdentifier, found: ext.oid)
            )
        }

        let asn1KeyIdentifier: AuthorityKeyIdentifierValue
        do {
            asn1KeyIdentifier = try AuthorityKeyIdentifierValue(derEncoded: ext.value)
        } catch {
            throw Certificate.Error.der(error)
        }
        self.keyIdentifier = asn1KeyIdentifier.keyIdentifier.map { $0.bytes }
        self.authorityCertIssuer = asn1KeyIdentifier.authorityCertIssuer
        self.authorityCertSerialNumber = asn1KeyIdentifier.authorityCertSerialNumber.map {
            Certificate.SerialNumber(bytes: $0)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: CustomStringConvertible {
    public var description: String {
        var elements: [String] = []

        if let keyId = self.keyIdentifier {
            elements.append("keyID: \(keyId.map { String($0, radix: 16) }.joined(separator: ":"))")
        }

        if let issuer = self.authorityCertIssuer {
            elements.append("issuer: \(issuer)")
        }

        if let serial = self.authorityCertSerialNumber {
            elements.append("issuerSerial: \(serial)")
        }

        return elements.joined(separator: ", ")
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: CustomDebugStringConvertible {
    public var debugDescription: String {
        "AuthorityKeyIdentifier(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {

    @inlinable
    public init(_ aki: AuthorityKeyIdentifier, critical: Bool) throws(ISO_8824.Error) {
        let asn1Representation = AuthorityKeyIdentifierValue(aki)
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.authorityKeyIdentifier,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}

@usableFromInline
struct AuthorityKeyIdentifierValue: ISO_8825.DER.ImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var keyIdentifier: ISO_8824.OctetString?

    @usableFromInline
    var authorityCertIssuer: [GeneralName]?

    @usableFromInline
    var authorityCertSerialNumber: ArraySlice<UInt8>?

    @inlinable
    init(
        keyIdentifier: ISO_8824.OctetString?,
        authorityCertIssuer: [GeneralName]?,
        authorityCertSerialNumber: ArraySlice<UInt8>?
    ) {
        self.keyIdentifier = keyIdentifier
        self.authorityCertIssuer = authorityCertIssuer
        self.authorityCertSerialNumber = authorityCertSerialNumber
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    init(_ aki: AuthorityKeyIdentifier) {
        self.keyIdentifier = aki.keyIdentifier.map { ISO_8824.OctetString(contentBytes: $0) }
        self.authorityCertIssuer = aki.authorityCertIssuer
        self.authorityCertSerialNumber = aki.authorityCertSerialNumber.map { $0.bytes }
    }

    @inlinable
    init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) {
            (
                nodes: inout ISO_8825.Node.Collection.Iterator
            ) throws(ISO_8824.Error) -> AuthorityKeyIdentifierValue in
            let keyIdentifier: ISO_8824.OctetString? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 0, tagClass: .contextSpecific)
            )
            let authorityCertIssuer: GeneralNames? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            let authorityCertSerialNumber: ArraySlice<UInt8>? = try ISO_8825.DER
                .optionalImplicitlyTagged(
                    &nodes,
                    tag: .init(tagWithNumber: 2, tagClass: .contextSpecific)
                )

            return AuthorityKeyIdentifierValue(
                keyIdentifier: keyIdentifier,
                authorityCertIssuer: authorityCertIssuer?.names,
                authorityCertSerialNumber: authorityCertSerialNumber
            )
        }
    }

    @inlinable
    func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serializeOptionalImplicitlyTagged(
                keyIdentifier,
                withIdentifier: .init(tagWithNumber: 0, tagClass: .contextSpecific)
            )
            try coder.serializeOptionalImplicitlyTagged(
                authorityCertIssuer.map { GeneralNames($0) },
                withIdentifier: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            try coder.serializeOptionalImplicitlyTagged(
                authorityCertSerialNumber,
                withIdentifier: .init(tagWithNumber: 2, tagClass: .contextSpecific)
            )
        }
    }
}
