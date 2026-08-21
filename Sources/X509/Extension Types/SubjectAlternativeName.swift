import ISO_8824
import ISO_8825

public struct SubjectAlternativeNames {
    @usableFromInline
    var names: [GeneralName]

    @inlinable
    public init<Names: Sequence>(_ names: Names) where Names.Element == GeneralName {
        self.names = Array(names)
    }

    @inlinable
    public init() {
        self.names = []
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws(Certificate.Error) {
        guard ext.oid == .X509ExtensionID.subjectAlternativeName else {
            throw Certificate.Error.extension(
                .incorrectOID(expected: .X509ExtensionID.subjectAlternativeName, found: ext.oid)
            )
        }

        let asn1SAN: GeneralNames
        do {
            asn1SAN = try GeneralNames(derEncoded: ext.value)
        } catch {
            throw Certificate.Error.der(error)
        }
        self.names = asn1SAN.names
    }
}

extension SubjectAlternativeNames: Hashable {}

extension SubjectAlternativeNames: Sendable {}

extension SubjectAlternativeNames: CustomStringConvertible {
    public var description: String {
        self.lazy.map { String(reflecting: $0) }.joined(separator: ", ")
    }
}

extension SubjectAlternativeNames: CustomDebugStringConvertible {
    public var debugDescription: String {
        "SubjectAlternativeNames(\(String(describing: self)))"
    }
}

extension SubjectAlternativeNames: RandomAccessCollection, MutableCollection,
    RangeReplaceableCollection
{
    @inlinable
    public var startIndex: Int {
        self.names.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.names.endIndex
    }

    @inlinable
    public subscript(position: Int) -> GeneralName {
        get {
            self.names[position]
        }
        set {
            self.names[position] = newValue
        }
    }

    @inlinable
    public mutating func replaceSubrange<NewElements>(
        _ subrange: Range<Int>,
        with newElements: NewElements
    )
    where NewElements: Collection, GeneralName == NewElements.Element {
        self.names.replaceSubrange(subrange, with: newElements)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {

    @inlinable
    public init(_ san: SubjectAlternativeNames, critical: Bool) throws(ISO_8824.Error) {
        let asn1Representation = GeneralNames(san.names)
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.subjectAlternativeName,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}
