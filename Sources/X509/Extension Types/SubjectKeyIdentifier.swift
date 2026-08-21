import ISO_8824
import ISO_8825

public struct SubjectKeyIdentifier {
    public var keyIdentifier: ArraySlice<UInt8>

    @inlinable
    public init(keyIdentifier: ArraySlice<UInt8>) {
        self.keyIdentifier = keyIdentifier
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws(Certificate.Error) {
        guard ext.oid == .X509ExtensionID.subjectKeyIdentifier else {
            throw Certificate.Error.extension(
                .incorrectOID(expected: .X509ExtensionID.subjectKeyIdentifier, found: ext.oid)
            )
        }

        let asn1KeyIdentifier: ISO_8824.OctetString
        do {
            asn1KeyIdentifier = try ISO_8824.OctetString(derEncoded: ext.value)
        } catch {
            throw Certificate.Error.der(error)
        }
        self.keyIdentifier = asn1KeyIdentifier.bytes
    }
}

extension SubjectKeyIdentifier: Hashable {}

extension SubjectKeyIdentifier: Sendable {}

extension SubjectKeyIdentifier: CustomStringConvertible {
    public var description: String {
        return self.keyIdentifier.lazy.map { String($0, radix: 16) }.joined(separator: ":")
    }
}

extension SubjectKeyIdentifier: CustomDebugStringConvertible {
    public var debugDescription: String {
        "SubjectKeyIdentifier(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {

    @inlinable
    public init(_ ski: SubjectKeyIdentifier, critical: Bool) throws(ISO_8824.Error) {
        let asn1Representation = ISO_8824.OctetString(contentBytes: ski.keyIdentifier)
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.subjectKeyIdentifier,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}
