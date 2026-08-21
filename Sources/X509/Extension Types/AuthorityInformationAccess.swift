import ISO_8824
import ISO_8825

public struct AuthorityInformationAccess {
    @usableFromInline
    var descriptions: [AccessDescription]

    public init() {
        self.descriptions = []
    }

    @inlinable
    public init<Descriptions: Sequence>(_ descriptions: Descriptions)
    where Descriptions.Element == AccessDescription {
        self.descriptions = Array(descriptions)
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws(Certificate.Error) {
        guard ext.oid == .X509ExtensionID.authorityInformationAccess else {
            throw Certificate.Error.extension(
                .incorrectOID(expected: .X509ExtensionID.authorityInformationAccess, found: ext.oid)
            )
        }

        let aiaSyntax: AuthorityInfoAccessSyntax
        do {
            aiaSyntax = try AuthorityInfoAccessSyntax(derEncoded: ext.value)
        } catch {
            throw Certificate.Error.der(error)
        }
        self.descriptions = aiaSyntax.descriptions.map { AccessDescription($0) }
    }
}

extension AuthorityInformationAccess: Hashable {}

extension AuthorityInformationAccess: Sendable {}

extension AuthorityInformationAccess: CustomStringConvertible {
    public var description: String {
        return self.map { String(reflecting: $0) }.joined(separator: ", ")
    }
}

extension AuthorityInformationAccess: CustomDebugStringConvertible {
    public var debugDescription: String {
        "AuthorityInformationAccess(\(String(describing: self)))"
    }
}

extension AuthorityInformationAccess: RandomAccessCollection {
    @inlinable
    public var startIndex: Int {
        self.descriptions.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.descriptions.endIndex
    }

    @inlinable
    public subscript(position: Int) -> AccessDescription {
        get {
            self.descriptions[position]
        }
        set {
            self.descriptions[position] = newValue
        }
    }
}

extension AuthorityInformationAccess: RangeReplaceableCollection {
    @inlinable
    public mutating func replaceSubrange(
        _ subrange: Range<Int>,
        with newElements: some Collection<AccessDescription>
    ) {
        self.descriptions.replaceSubrange(subrange, with: newElements)
    }
}

extension AuthorityInformationAccess {

    public struct AccessDescription {

        public var method: AccessMethod

        public var location: GeneralName

        @inlinable
        public init(method: AccessMethod, location: GeneralName) {
            self.method = method
            self.location = location
        }

        @inlinable
        init(_ asn1Form: AIAAccessDescription) {
            self.method = .init(asn1Form.accessMethod)
            self.location = asn1Form.accessLocation
        }
    }
}

extension AuthorityInformationAccess.AccessDescription: Hashable {}

extension AuthorityInformationAccess.AccessDescription: Sendable {}

extension AuthorityInformationAccess.AccessDescription: CustomStringConvertible {
    public var description: String {
        return "\(self.method): \(self.location)"
    }
}

extension AuthorityInformationAccess.AccessDescription: CustomDebugStringConvertible {
    public var debugDescription: String {
        "(\(String(describing: self)))"
    }
}

extension AuthorityInformationAccess.AccessDescription {

    public struct AccessMethod {
        @usableFromInline
        var backing: Backing

        @usableFromInline
        enum Backing {
            case ocspServer
            case issuingCA
            case unknownType(ISO_8824.ObjectIdentifier)
        }

        @inlinable
        init(_ backing: Backing) {
            self.backing = backing
        }

        @inlinable
        package init(_ oid: ISO_8824.ObjectIdentifier) {
            switch oid {
            case .AccessMethodIdentifiers.ocspServer:
                self.backing = .ocspServer

            case .AccessMethodIdentifiers.issuingCA:
                self.backing = .issuingCA

            default:
                self.backing = .unknownType(oid)
            }
        }

        public static let ocspServer = Self(.ocspServer)

        public static let issuingCA = Self(.issuingCA)
    }
}

extension AuthorityInformationAccess.AccessDescription.AccessMethod: Hashable {}

extension AuthorityInformationAccess.AccessDescription.AccessMethod: Sendable {}

extension AuthorityInformationAccess.AccessDescription.AccessMethod: CustomStringConvertible {
    @inlinable
    public var description: String {
        switch self.backing {
        case .ocspServer:
            return "OCSP Server"

        case .issuingCA:
            return "Issuer"

        case .unknownType(let oid):
            return String(describing: oid)
        }
    }
}

extension AuthorityInformationAccess.AccessDescription.AccessMethod: CustomDebugStringConvertible {
    public var debugDescription: String {
        switch self.backing {
        case .ocspServer:
            return "\"OCSP Server\""

        case .issuingCA:
            return "\"Issuer\""

        case .unknownType(let oid):
            return String(reflecting: oid)
        }
    }
}

extension AuthorityInformationAccess.AccessDescription.AccessMethod.Backing: Hashable {}

extension AuthorityInformationAccess.AccessDescription.AccessMethod.Backing: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {

    @inlinable
    public init(_ aia: AuthorityInformationAccess, critical: Bool) throws(ISO_8824.Error) {
        let asn1Representation = AuthorityInfoAccessSyntax(aia)
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.authorityInformationAccess,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}

@usableFromInline
struct AuthorityInfoAccessSyntax: ISO_8825.DER.ImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var descriptions: [AIAAccessDescription]

    @inlinable
    init(_ aia: AuthorityInformationAccess) {
        self.descriptions = aia.descriptions.map { .init($0) }
    }

    @inlinable
    init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self.descriptions = try ISO_8825.DER.sequence(
            of: AIAAccessDescription.self,
            identifier: identifier,
            rootNode: rootNode
        )
    }

    @inlinable
    func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for description in descriptions {
                try coder.serialize(description)
            }
        }
    }
}

@usableFromInline
struct AIAAccessDescription: ISO_8825.DER.ImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var accessMethod: ISO_8824.ObjectIdentifier

    @usableFromInline
    var accessLocation: GeneralName

    @inlinable
    init(accessMethod: ISO_8824.ObjectIdentifier, accessLocation: GeneralName) {
        self.accessMethod = accessMethod
        self.accessLocation = accessLocation
    }

    @inlinable
    init(_ description: AuthorityInformationAccess.AccessDescription) {
        self.accessMethod = ISO_8824.ObjectIdentifier(accessMethod: description.method)
        self.accessLocation = description.location
    }

    @inlinable
    init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) {
            (
                nodes: inout ISO_8825.Node.Collection.Iterator
            ) throws(ISO_8824.Error) -> AIAAccessDescription in
            let accessMethod = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let accessLocation = try GeneralName(derEncoded: &nodes)
            return AIAAccessDescription(accessMethod: accessMethod, accessLocation: accessLocation)
        }
    }

    @inlinable
    func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(accessMethod)
            try coder.serialize(accessLocation)
        }
    }
}

extension ISO_8824.ObjectIdentifier {
    @usableFromInline
    enum AccessMethodIdentifiers: Sendable {
        @usableFromInline
        static let ocspServer: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 48, 1]

        @usableFromInline
        static let issuingCA: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 48, 2]
    }

    @inlinable
    public init(accessMethod: AuthorityInformationAccess.AccessDescription.AccessMethod) {
        switch accessMethod.backing {
        case .ocspServer:
            self = .AccessMethodIdentifiers.ocspServer

        case .issuingCA:
            self = .AccessMethodIdentifiers.issuingCA

        case .unknownType(let oid):
            self = oid
        }
    }
}
