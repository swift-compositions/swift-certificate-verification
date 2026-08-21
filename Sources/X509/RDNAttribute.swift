import ISO_8824
import ISO_8825

extension RelativeDistinguishedName {

    public struct Attribute {
        public struct Value: Hashable, Sendable {
            @usableFromInline
            enum Storage: Hashable, Sendable {

                case printable(String)

                case utf8(String)

                case ia5(String)

                case any(ISO_8825.`Any`)
            }

            @usableFromInline
            var storage: Storage

            @inlinable
            init(storage: Storage) {
                self.storage = storage
            }
        }

        public var type: ISO_8824.ObjectIdentifier

        public var value: Attribute.Value

        @inlinable
        public init(type: ISO_8824.ObjectIdentifier, value: Attribute.Value) {
            self.type = type
            self.value = value
        }
    }
}

extension ISO_8825.`Any` {
    @inlinable
    init(_ storage: RelativeDistinguishedName.Attribute.Value.Storage) {
        switch storage {
        case .printable(let printableString):

            self = try! .init(erasing: ISO_8824.PrintableString(printableString))

        case .utf8(let utf8String):

            self = try! .init(erasing: ISO_8824.UTF8String(utf8String))

        case .ia5(let ia5String):

            self = try! .init(erasing: ISO_8824.IA5String(ia5String))

        case .any(let any):
            self = any
        }
    }
}

extension ISO_8825.`Any` {
    @inlinable
    public init(_ value: RelativeDistinguishedName.Attribute.Value) {
        self = ISO_8825.`Any`(value.storage)
    }
}

extension RelativeDistinguishedName.Attribute.Value {

    @inlinable
    public init(utf8String: String) {
        self.storage = .utf8(utf8String)
    }

    @inlinable
    public init(printableString: String) throws(ISO_8824.Error) {

        _ = try ISO_8824.PrintableString(printableString)
        self.storage = .printable(printableString)
    }

    @inlinable
    public init(ia5String: String) throws(ISO_8824.Error) {

        _ = try ISO_8824.IA5String(ia5String)
        self.storage = .ia5(ia5String)
    }

    @inlinable
    public init(asn1Any: ISO_8825.`Any`) {
        do {
            self.storage = try .init(asn1Any: asn1Any)
        } catch {
            self.storage = .any(asn1Any)
        }
    }
}

extension RelativeDistinguishedName.Attribute.Value.Storage: ISO_8825.DER.Parseable, ISO_8825.DER
        .Serializable
{
    @inlinable
    init(derEncoded node: ISO_8825.Node) throws(ISO_8824.Error) {
        do {
            switch node.identifier {
            case ISO_8824.UTF8String.defaultIdentifier:
                self = .utf8(String(try ISO_8824.UTF8String(derEncoded: node)))

            case ISO_8824.PrintableString.defaultIdentifier:
                self = .printable(String(try ISO_8824.PrintableString(derEncoded: node)))

            case ISO_8824.IA5String.defaultIdentifier:
                self = .ia5(String(try ISO_8824.IA5String(derEncoded: node)))

            default:
                self = .any(ISO_8825.`Any`(derEncoded: node))
            }
        } catch {
            self = .any(ISO_8825.`Any`(derEncoded: node))
        }
    }

    @inlinable
    func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .printable(let printableString):

            let printableString = try! ISO_8824.PrintableString(printableString)
            try printableString.serialize(into: &coder)

        case .utf8(let utf8String):
            let string = ISO_8824.UTF8String(utf8String)
            try string.serialize(into: &coder)

        case .ia5(let ia5String):

            let string = try! ISO_8824.IA5String(ia5String)
            try string.serialize(into: &coder)

        case .any(let any):
            try any.serialize(into: &coder)
        }
    }
}

extension RelativeDistinguishedName.Attribute.Value: CustomStringConvertible {
    @inlinable
    public var description: String {
        let text: String
        if let string = String(self) {
            text = string
        } else {
            text = String(describing: ISO_8825.`Any`(self))
        }

        let unescapedBytes = Array(text.utf8)
        let charsToEscape: [UInt8] = [
            UInt8(ascii: "," as Unicode.Scalar), UInt8(ascii: "+" as Unicode.Scalar),
            UInt8(ascii: "\"" as Unicode.Scalar), UInt8(ascii: "\\" as Unicode.Scalar),
            UInt8(ascii: "<" as Unicode.Scalar), UInt8(ascii: ">" as Unicode.Scalar),
            UInt8(ascii: ";" as Unicode.Scalar),
        ]

        let leadingBytesToEscape = unescapedBytes.prefix(while: {
            $0 == UInt8(ascii: " " as Unicode.Scalar) || $0 == UInt8(ascii: "#" as Unicode.Scalar)
        })

        let trailingBytesToEscape = unescapedBytes.dropFirst(leadingBytesToEscape.count).suffix(
            while: {
                $0 == UInt8(ascii: " " as Unicode.Scalar)
            })
        let middleBytes = unescapedBytes[
            leadingBytesToEscape.endIndex..<trailingBytesToEscape.startIndex
        ]

        var escapedBytes = leadingBytesToEscape.flatMap {
            [UInt8(ascii: "\\" as Unicode.Scalar), $0]
        }
        escapedBytes += middleBytes.flatMap {
            guard charsToEscape.contains($0) else {
                return [$0]
            }
            return [UInt8(ascii: "\\" as Unicode.Scalar), $0]
        }
        escapedBytes += trailingBytesToEscape.flatMap {
            [UInt8(ascii: "\\" as Unicode.Scalar), $0]
        }

        return String(decoding: escapedBytes, as: UTF8.self)
    }
}

extension RelativeDistinguishedName.Attribute.Value: CustomDebugStringConvertible {
    public var debugDescription: String {
        String(reflecting: String(describing: self))
    }
}

extension RelativeDistinguishedName.Attribute: Hashable {}

extension RelativeDistinguishedName.Attribute: Sendable {}

extension RelativeDistinguishedName.Attribute: CustomStringConvertible {
    @inlinable
    public var description: String {
        let attributeKey: String
        switch self.type {
        case .RDNAttributeType.commonName:
            attributeKey = "CN"

        case .RDNAttributeType.countryName:
            attributeKey = "C"

        case .RDNAttributeType.localityName:
            attributeKey = "L"

        case .RDNAttributeType.stateOrProvinceName:
            attributeKey = "ST"

        case .RDNAttributeType.organizationName:
            attributeKey = "O"

        case .RDNAttributeType.organizationalUnitName:
            attributeKey = "OU"

        case .RDNAttributeType.streetAddress:
            attributeKey = "STREET"

        case .RDNAttributeType.domainComponent:
            attributeKey = "DC"

        case .RDNAttributeType.emailAddress:
            attributeKey = "E"

        case let type:
            attributeKey = String(describing: type)
        }

        return "\(attributeKey)=\(value)"
    }
}

extension RelativeDistinguishedName.Attribute: ISO_8825.DER.ImplicitlyTaggable {
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
            ) throws(ISO_8824.Error) -> RelativeDistinguishedName.Attribute in
            let type = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let value = try Value(storage: .init(derEncoded: &nodes))
            return .init(type: type, value: value)
        }
    }

    @inlinable
    public func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.type)
            try coder.serialize(self.value.storage)
        }
    }
}

extension RelativeDistinguishedName.Attribute {

    @inlinable
    public init(type: ISO_8824.ObjectIdentifier, utf8String: String) {
        self.type = type
        self.value = .init(utf8String: utf8String)
    }

    @inlinable
    public init(type: ISO_8824.ObjectIdentifier, printableString: String) throws(ISO_8824.Error) {
        self.type = type
        self.value = try .init(printableString: printableString)
    }

    @inlinable
    public init(type: ISO_8824.ObjectIdentifier, ia5String: String) throws(ISO_8824.Error) {
        self.type = type
        self.value = try .init(ia5String: ia5String)
    }

    @inlinable
    public init(type: ISO_8824.ObjectIdentifier, value: ISO_8825.`Any`) {
        self.type = type
        self.value = .init(asn1Any: value)
    }
}

extension ISO_8824.ObjectIdentifier {

    public enum RDNAttributeType: Sendable {

        public static let countryName: ISO_8824.ObjectIdentifier = [2, 5, 4, 6]

        public static let commonName: ISO_8824.ObjectIdentifier = [2, 5, 4, 3]

        public static let localityName: ISO_8824.ObjectIdentifier = [2, 5, 4, 7]

        public static let stateOrProvinceName: ISO_8824.ObjectIdentifier = [2, 5, 4, 8]

        public static let organizationName: ISO_8824.ObjectIdentifier = [2, 5, 4, 10]

        public static let organizationalUnitName: ISO_8824.ObjectIdentifier = [2, 5, 4, 11]

        public static let streetAddress: ISO_8824.ObjectIdentifier = [2, 5, 4, 9]

        public static let domainComponent: ISO_8824.ObjectIdentifier = [
            0, 9, 2342, 19_200_300, 100, 1, 25,
        ]

        public static let emailAddress: ISO_8824.ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 1]
    }
}

extension String {

    public init?(_ value: RelativeDistinguishedName.Attribute.Value) {
        switch value.storage {
        case .printable(let printable):
            self = printable

        case .utf8(let utf8):
            self = utf8

        case .ia5(let ia5):
            self = ia5

        case .any:
            return nil
        }
    }
}

extension RandomAccessCollection {
    @inlinable
    package func suffix(while predicate: (Element) -> Bool) -> SubSequence {
        var index = self.endIndex
        if index == self.startIndex {
            return self[...]
        }

        repeat {
            self.formIndex(before: &index)
            if !predicate(self[index]) {
                self.formIndex(after: &index)
                break
            }
        } while index != self.startIndex

        return self[index..<self.endIndex]
    }
}
