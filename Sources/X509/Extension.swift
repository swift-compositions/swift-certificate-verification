import ISO_8824
import ISO_8825

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public struct Extension {

        public var oid: ISO_8824.ObjectIdentifier

        public var critical: Bool

        public var value: ArraySlice<UInt8>

        @inlinable
        public init(oid: ISO_8824.ObjectIdentifier, critical: Bool, value: ArraySlice<UInt8>) {
            self.oid = oid
            self.critical = critical
            self.value = value
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension: CustomStringConvertible {
    public var description: String {

        do { return String(reflecting: try AuthorityInformationAccess(self)) } catch {}
        do { return String(reflecting: try SubjectKeyIdentifier(self)) } catch {}
        do { return String(reflecting: try AuthorityKeyIdentifier(self)) } catch {}
        do { return String(reflecting: try ExtendedKeyUsage(self)) } catch {}
        do { return String(reflecting: try BasicConstraints(self)) } catch {}
        do { return String(reflecting: try KeyUsage(self)) } catch {}
        do { return String(reflecting: try NameConstraints(self)) } catch {}
        do { return String(reflecting: try SubjectAlternativeNames(self)) } catch {}
        return """
            Extension(\
            oid: \(String(reflecting: self.oid)), \
            critical: \(String(reflecting: self.critical)), \
            value: \(self.value.count) bytes\
            )
            """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension: ISO_8825.DER.ImplicitlyTaggable {
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
            ) throws(ISO_8824.Error) -> Certificate.Extension in
            let extensionID = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let critical = try ISO_8825.DER.decodeDefault(&nodes, defaultValue: false)
            let value = try ISO_8824.OctetString(derEncoded: &nodes)

            return Certificate.Extension(oid: extensionID, critical: critical, value: value.bytes)
        }
    }

    @inlinable
    public func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.oid)

            if self.critical {
                try coder.serialize(self.critical)
            }

            try coder.serialize(ISO_8824.OctetString(contentBytes: self.value))
        }
    }
}
