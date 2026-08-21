import ISO_8824
import ISO_8825

public struct DistinguishedName {
    @usableFromInline
    var rdns: [RelativeDistinguishedName]

    @inlinable
    public init<RDNSequence: Sequence>(_ rdns: RDNSequence)
    where RDNSequence.Element == RelativeDistinguishedName {
        self.rdns = Array(rdns)
    }

    @inlinable
    public init<AttributeSequence: Sequence>(
        _ attributes: AttributeSequence
    ) throws(Certificate.Error)
    where AttributeSequence.Element == RelativeDistinguishedName.Attribute {
        self.rdns = attributes.map { RelativeDistinguishedName($0) }
    }

    @inlinable
    public init() {
        self.rdns = []
    }
}

extension DistinguishedName: Hashable {}

extension DistinguishedName: Sendable {}

extension DistinguishedName: RandomAccessCollection, MutableCollection, RangeReplaceableCollection {
    @inlinable
    public var startIndex: Int {
        self.rdns.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.rdns.endIndex
    }

    @inlinable
    public subscript(position: Int) -> RelativeDistinguishedName {
        get {
            self.rdns[position]
        }
        set {
            self.rdns[position] = newValue
        }
    }

    @inlinable
    public mutating func replaceSubrange<NewElements>(
        _ subrange: Range<Int>,
        with newElements: NewElements
    )
    where NewElements: Collection, RelativeDistinguishedName == NewElements.Element {
        self.rdns.replaceSubrange(subrange, with: newElements)
    }
}

extension DistinguishedName: CustomStringConvertible {
    @inlinable
    public var description: String {
        self.reversed().lazy.map { String(describing: $0) }.joined(separator: ",")
    }
}

extension DistinguishedName: CustomDebugStringConvertible {
    public var debugDescription: String {
        String(reflecting: String(describing: self))
    }
}

extension DistinguishedName: ISO_8825.DER.Serializable {
    @inlinable
    public func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: .sequence) {
            (rootCoder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for element in self.rdns {
                try element.serialize(into: &rootCoder)
            }
        }
    }
}

extension DistinguishedName: ISO_8825.DER.Parseable {
    @inlinable
    public init(derEncoded rootNode: ISO_8825.Node) throws(ISO_8824.Error) {
        self.rdns = try ISO_8825.DER.sequence(
            of: RelativeDistinguishedName.self,
            identifier: .sequence,
            rootNode: rootNode
        )
    }

    @inlinable
    package static func derEncoded(
        _ sequenceNodeIterator: inout ISO_8825.Node.Collection.Iterator
    ) throws(ISO_8824.Error) -> DistinguishedName {

        let dnFactory:
            (inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> DistinguishedName =
                DistinguishedName.init(derEncoded:)
        return try dnFactory(&sequenceNodeIterator)
    }
}

@available(*, deprecated, message: "Distinguished names may not be implicitly tagged")
extension DistinguishedName: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @inlinable
    public init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self.rdns = try ISO_8825.DER.sequence(
            of: RelativeDistinguishedName.self,
            identifier: identifier,
            rootNode: rootNode
        )
    }

    @inlinable
    public func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (rootCoder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for element in self.rdns {
                try element.serialize(into: &rootCoder)
            }
        }
    }
}
