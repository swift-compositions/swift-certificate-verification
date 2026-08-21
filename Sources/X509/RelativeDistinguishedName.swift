import Certificate_Internals
import ISO_8824
import ISO_8825

public struct RelativeDistinguishedName {
    @usableFromInline
    var attributes: _TinyArray<Attribute>

    @inlinable
    public init<AttributeSequence: Sequence>(_ attributes: AttributeSequence)
    where AttributeSequence.Element == RelativeDistinguishedName.Attribute {
        self.attributes = .init(attributes)
        Self._sortElements(&self.attributes)
    }

    @inlinable
    public init(_ attribute: Attribute) {
        self.init(CollectionOfOne(attribute))
    }

    @inlinable
    package init(_ attributes: ISO_8825.DER.LazySetOfSequence<Attribute>) throws(ISO_8824.Error) {

        do {
            self.attributes = try .init(attributes)
        } catch let error as ISO_8824.Error {
            throw error
        } catch {
            throw ISO_8824.Error.invalidASN1Object(reason: "\(error)")
        }
        Self._sortElements(&self.attributes)
    }

    @inlinable
    public init() {
        self.attributes = .init()
    }
}

extension RelativeDistinguishedName: Hashable {}

extension RelativeDistinguishedName: Sendable {}

extension RelativeDistinguishedName: RandomAccessCollection {
    @inlinable
    public var startIndex: Int {
        self.attributes.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.attributes.endIndex
    }

    @inlinable
    public subscript(position: Int) -> RelativeDistinguishedName.Attribute {
        self.attributes[position]
    }

    @inlinable
    public mutating func insert(_ attribute: RelativeDistinguishedName.Attribute) {
        self.attributes.append(attribute)
        Self._sortElements(&self.attributes)
    }

    @inlinable
    public mutating func insert<Attributes: Collection>(contentsOf attributes: Attributes)
    where Attributes.Element == RelativeDistinguishedName.Attribute {
        self.attributes.append(contentsOf: attributes)
        Self._sortElements(&self.attributes)
    }

    @inlinable
    @discardableResult
    public mutating func remove(at index: Int) -> Element {
        self.attributes.remove(at: index)

    }

    @inlinable
    public mutating func removeAll(where shouldBeRemoved: (Attribute) throws -> Bool) rethrows {
        try self.attributes.removeAll(where: shouldBeRemoved)

    }
}

extension RelativeDistinguishedName: CustomStringConvertible {
    @inlinable
    public var description: String {
        self.lazy.map {
            String(describing: $0)
        }.joined(separator: "+")
    }
}

extension RelativeDistinguishedName: CustomDebugStringConvertible {
    public var debugDescription: String {
        String(reflecting: String(describing: self))
    }
}

extension RelativeDistinguishedName: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        .set
    }

    @inlinable
    public init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try self.init(ISO_8825.DER.lazySet(identifier: identifier, rootNode: rootNode))
    }

    @inlinable
    public func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.serializeSetOf(self.attributes, identifier: identifier)
    }

    @inlinable
    package static func _sortElements(
        _ elements: inout _TinyArray<RelativeDistinguishedName.Attribute>
    ) {

        try! elements.sort { lhs, rhs in
            var serializer = ISO_8825.DER.Serializer()
            try serializer.serialize(lhs)
            let lhsBytes = serializer.serializedBytes

            serializer = ISO_8825.DER.Serializer()
            try serializer.serialize(rhs)
            let rhsBytes = serializer.serializedBytes

            for (leftByte, rightByte) in zip(lhsBytes, rhsBytes) {
                if leftByte < rightByte {

                    return true
                } else if rightByte < leftByte {

                    return false
                }
            }

            let trailing = rhsBytes.dropFirst(lhsBytes.count)
            if trailing.count == 0 || trailing.allSatisfy({ $0 == 0 }) {

                return false
            }
            return true
        }
    }
}
