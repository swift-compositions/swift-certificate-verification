import ISO_8824
import ISO_8825
import Standard_Library_Extensions

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct NameConstraints {
    public struct DNSNames: Hashable, Sendable, Collection, ExpressibleByArrayLiteral,
        CustomStringConvertible
    {
        public typealias Element = String

        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.elementsEqual(rhs)
        }

        @usableFromInline
        var subtrees: [GeneralName]

        @inlinable
        public var description: String {
            "[\(self.joined(separator: ", "))]"
        }

        @inlinable
        package init(subtrees: [GeneralName]) {
            self.subtrees = subtrees
        }

        @inlinable
        public init(_ elements: some Sequence<String>) {
            self.subtrees = elements.map { .dnsName($0) }
        }

        @inlinable
        public init(arrayLiteral elements: String...) {
            self.init(elements)
        }

        @inlinable
        public func hash(into hasher: inout Hasher) {
            hasher.combine(contentsOf: self)
        }

        public struct Index: Comparable, Sendable {
            @inlinable
            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.wrapped < rhs.wrapped
            }
            @usableFromInline
            var wrapped: Int

            @inlinable
            package init(_ wrapped: Int) {
                self.wrapped = wrapped
            }
        }

        @inlinable
        public var startIndex: Index {
            Index(
                self.subtrees.firstIndex(where: {
                    guard case .dnsName = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public var endIndex: Index {
            Index(self.subtrees.endIndex)
        }

        @inlinable
        public func index(after i: Index) -> Index {
            Index(
                self.subtrees[i.wrapped...].dropFirst().firstIndex(where: {
                    guard case .dnsName = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public subscript(position: Index) -> String {
            guard case .dnsName(let name) = self.subtrees[position.wrapped] else {
                fatalError("index \(position) is not a valid index for \(Self.self)")
            }
            return name
        }

        @inlinable
        package var filtered: some Sequence<GeneralName> {
            self.subtrees.lazy.filter {
                guard case .dnsName = $0 else {
                    return false
                }
                return true
            }
        }
    }

    public struct IPRanges: Hashable, Sendable, Collection, ExpressibleByArrayLiteral,
        CustomStringConvertible
    {
        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.elementsEqual(rhs)
        }

        @usableFromInline
        var subtrees: [GeneralName]

        @inlinable
        public var description: String {
            "[\(self.lazy.map { String(describing: $0.bytes) }.joined(separator: ", "))]"
        }

        @inlinable
        package init(subtrees: [GeneralName]) {
            self.subtrees = subtrees
        }

        @inlinable
        public init(_ elements: some Sequence<ISO_8824.OctetString>) {
            self.subtrees = elements.map { .ipAddress($0) }
        }

        @inlinable
        public init(arrayLiteral elements: ISO_8824.OctetString...) {
            self.init(elements)
        }

        @inlinable
        public func hash(into hasher: inout Hasher) {
            hasher.combine(contentsOf: self)
        }

        public struct Index: Comparable, Sendable {
            @inlinable
            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.wrapped < rhs.wrapped
            }
            @usableFromInline
            var wrapped: Int

            @inlinable
            package init(_ wrapped: Int) {
                self.wrapped = wrapped
            }
        }

        @inlinable
        public var startIndex: Index {
            Index(
                self.subtrees.firstIndex(where: {
                    guard case .ipAddress = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public var endIndex: Index {
            Index(self.subtrees.endIndex)
        }

        @inlinable
        public func index(after i: Index) -> Index {
            Index(
                self.subtrees[i.wrapped...].dropFirst().firstIndex(where: {
                    guard case .ipAddress = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public subscript(position: Index) -> ISO_8824.OctetString {
            guard case .ipAddress(let ipAddress) = self.subtrees[position.wrapped] else {
                fatalError("index \(position) is not a valid index for \(Self.self)")
            }
            return ipAddress
        }

        @inlinable
        package var filtered: some Sequence<GeneralName> {
            self.subtrees.lazy.filter {
                guard case .ipAddress = $0 else {
                    return false
                }
                return true
            }
        }
    }

    public struct EmailAddresses: Hashable, Sendable, Collection, ExpressibleByArrayLiteral,
        CustomStringConvertible
    {
        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.elementsEqual(rhs)
        }

        @usableFromInline
        var subtrees: [GeneralName]

        @inlinable
        public var description: String {
            "[\(self.joined(separator: ", "))]"
        }

        @inlinable
        package init(subtrees: [GeneralName]) {
            self.subtrees = subtrees
        }

        @inlinable
        public init(_ elements: some Sequence<String>) {
            self.subtrees = elements.map { .rfc822Name($0) }
        }

        @inlinable
        public init(arrayLiteral elements: String...) {
            self.init(elements)
        }

        @inlinable
        public func hash(into hasher: inout Hasher) {
            hasher.combine(contentsOf: self)
        }

        public struct Index: Comparable, Sendable {
            @inlinable
            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.wrapped < rhs.wrapped
            }
            @usableFromInline
            var wrapped: Int

            @inlinable
            package init(_ wrapped: Int) {
                self.wrapped = wrapped
            }
        }

        @inlinable
        public var startIndex: Index {
            Index(
                self.subtrees.firstIndex(where: {
                    guard case .rfc822Name = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public var endIndex: Index {
            Index(self.subtrees.endIndex)
        }

        @inlinable
        public func index(after i: Index) -> Index {
            Index(
                self.subtrees[i.wrapped...].dropFirst().firstIndex(where: {
                    guard case .rfc822Name = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public subscript(position: Index) -> String {
            guard case .rfc822Name(let emailAddress) = self.subtrees[position.wrapped] else {
                fatalError("index \(position) is not a valid index for \(Self.self)")
            }
            return emailAddress
        }

        @inlinable
        package var filtered: some Sequence<GeneralName> {
            self.subtrees.lazy.filter {
                guard case .rfc822Name = $0 else {
                    return false
                }
                return true
            }
        }
    }

    public struct URIDomains: Hashable, Sendable, Collection, ExpressibleByArrayLiteral,
        CustomStringConvertible
    {
        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.elementsEqual(rhs)
        }

        @usableFromInline
        var subtrees: [GeneralName]

        @inlinable
        public var description: String {
            "[\(self.joined(separator: ", "))]"
        }

        @inlinable
        package init(subtrees: [GeneralName]) {
            self.subtrees = subtrees
        }

        @inlinable
        public init(_ elements: some Sequence<String>) {
            self.subtrees = elements.map { .uniformResourceIdentifier($0) }
        }

        @inlinable
        public init(arrayLiteral elements: String...) {
            self.init(elements)
        }

        @inlinable
        public func hash(into hasher: inout Hasher) {
            hasher.combine(contentsOf: self)
        }

        public struct Index: Comparable, Sendable {
            @inlinable
            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.wrapped < rhs.wrapped
            }
            @usableFromInline
            var wrapped: Int

            @inlinable
            package init(_ wrapped: Int) {
                self.wrapped = wrapped
            }
        }

        @inlinable
        public var startIndex: Index {
            Index(
                self.subtrees.firstIndex(where: {
                    guard case .uniformResourceIdentifier = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public var endIndex: Index {
            Index(self.subtrees.endIndex)
        }

        @inlinable
        public func index(after i: Index) -> Index {
            Index(
                self.subtrees[i.wrapped...].dropFirst().firstIndex(where: {
                    guard case .uniformResourceIdentifier = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public subscript(position: Index) -> String {
            guard case .uniformResourceIdentifier(let uri) = self.subtrees[position.wrapped] else {
                fatalError("index \(position) is not a valid index for \(Self.self)")
            }
            return uri
        }

        @inlinable
        package var filtered: some Sequence<GeneralName> {
            self.subtrees.lazy.filter {
                guard case .uniformResourceIdentifier = $0 else {
                    return false
                }
                return true
            }
        }
    }

    public internal(set) var permittedDNSDomains: DNSNames {
        get {
            DNSNames(subtrees: permittedSubtrees)
        }
        set {
            permittedSubtrees.removeAll {
                guard case .dnsName = $0 else {
                    return false
                }
                return true
            }
            permittedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    public internal(set) var excludedDNSDomains: DNSNames {
        get {
            DNSNames(subtrees: excludedSubtrees)
        }
        set {
            excludedSubtrees.removeAll {
                guard case .dnsName = $0 else {
                    return false
                }
                return true
            }
            excludedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    public internal(set) var permittedIPRanges: IPRanges {
        get {
            IPRanges(subtrees: permittedSubtrees)
        }
        set {
            permittedSubtrees.removeAll {
                guard case .ipAddress = $0 else {
                    return false
                }
                return true
            }
            permittedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    public internal(set) var excludedIPRanges: IPRanges {
        get {
            IPRanges(subtrees: excludedSubtrees)
        }
        set {
            excludedSubtrees.removeAll {
                guard case .ipAddress = $0 else {
                    return false
                }
                return true
            }
            excludedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    public internal(set) var permittedEmailAddresses: EmailAddresses {
        get {
            EmailAddresses(subtrees: permittedSubtrees)
        }
        set {
            permittedSubtrees.removeAll {
                guard case .rfc822Name = $0 else {
                    return false
                }
                return true
            }
            permittedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    public internal(set) var excludedEmailAddresses: EmailAddresses {
        get {
            EmailAddresses(subtrees: excludedSubtrees)
        }
        set {
            excludedSubtrees.removeAll {
                guard case .rfc822Name = $0 else {
                    return false
                }
                return true
            }
            excludedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    public internal(set) var permittedURIDomains: URIDomains {
        get {
            URIDomains(subtrees: permittedSubtrees)
        }
        set {
            permittedSubtrees.removeAll {
                guard case .uniformResourceIdentifier = $0 else {
                    return false
                }
                return true
            }
            permittedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    public internal(set) var forbiddenURIDomains: URIDomains {
        get {
            URIDomains(subtrees: excludedSubtrees)
        }
        set {
            excludedSubtrees.removeAll {
                guard case .uniformResourceIdentifier = $0 else {
                    return false
                }
                return true
            }
            excludedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    public var permittedSubtrees: [GeneralName]

    public var excludedSubtrees: [GeneralName]

    @inlinable
    public init(
        permittedDNSDomains: some Sequence<String> = [],
        excludedDNSDomains: some Sequence<String> = [],
        permittedIPRanges: some Sequence<ISO_8824.OctetString> = [],
        excludedIPRanges: some Sequence<ISO_8824.OctetString> = [],
        permittedEmailAddresses: some Sequence<String> = [],
        excludedEmailAddresses: some Sequence<String> = [],
        permittedURIDomains: some Sequence<String> = [],
        forbiddenURIDomains: some Sequence<String> = []
    ) {
        self.permittedSubtrees = []
        self.permittedSubtrees.reserveCapacity(
            permittedDNSDomains.underestimatedCount + permittedIPRanges.underestimatedCount
                + permittedEmailAddresses.underestimatedCount
                + permittedURIDomains.underestimatedCount
        )
        self.permittedSubtrees.append(contentsOf: permittedDNSDomains.lazy.map { .dnsName($0) })
        self.permittedSubtrees.append(contentsOf: permittedIPRanges.lazy.map { .ipAddress($0) })
        self.permittedSubtrees.append(
            contentsOf: permittedEmailAddresses.lazy.map { .rfc822Name($0) }
        )
        self.permittedSubtrees.append(
            contentsOf: permittedURIDomains.lazy.map { .uniformResourceIdentifier($0) }
        )

        self.excludedSubtrees = []
        self.excludedSubtrees.reserveCapacity(
            excludedDNSDomains.underestimatedCount + excludedIPRanges.underestimatedCount
                + excludedEmailAddresses.underestimatedCount
                + forbiddenURIDomains.underestimatedCount
        )
        self.excludedSubtrees.append(contentsOf: excludedDNSDomains.lazy.map { .dnsName($0) })
        self.excludedSubtrees.append(contentsOf: excludedIPRanges.lazy.map { .ipAddress($0) })
        self.excludedSubtrees.append(
            contentsOf: excludedEmailAddresses.lazy.map { .rfc822Name($0) }
        )
        self.excludedSubtrees.append(
            contentsOf: forbiddenURIDomains.lazy.map { .uniformResourceIdentifier($0) }
        )
    }

    @inlinable
    public init(
        permittedSubtrees: [GeneralName] = [],
        excludedSubtrees: [GeneralName] = []
    ) {
        self.permittedSubtrees = permittedSubtrees
        self.excludedSubtrees = excludedSubtrees
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws(Certificate.Error) {
        guard ext.oid == .X509ExtensionID.nameConstraints else {
            throw Certificate.Error.extension(
                .incorrectOID(expected: .X509ExtensionID.nameConstraints, found: ext.oid)
            )
        }

        let nameConstraintsValue: NameConstraintsValue
        do {
            nameConstraintsValue = try NameConstraintsValue(derEncoded: ext.value)
        } catch {
            throw Certificate.Error.der(error)
        }
        guard
            nameConstraintsValue.permittedSubtrees != nil
                || nameConstraintsValue.excludedSubtrees != nil
        else {
            throw Certificate.Error.der(
                .invalidASN1Object(
                    reason: "Name Constraints has no permitted or excluded subtrees"
                )
            )
        }

        self.permittedSubtrees = nameConstraintsValue.permittedSubtrees ?? []
        self.excludedSubtrees = nameConstraintsValue.excludedSubtrees ?? []
    }
}

extension Hasher {
    @inlinable
    package mutating func combine(contentsOf elements: some Sequence<some Hashable>) {
        for element in elements {
            self.combine(element)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: CustomStringConvertible {
    public var description: String {
        var elements: [String] = []

        if self.permittedSubtrees.count > 0 {
            elements.append(
                "permittedSubtrees: [\(self.permittedSubtrees.map { String(reflecting: $0) }.joined(separator: ", "))]"
            )
        }
        if self.excludedSubtrees.count > 0 {
            elements.append(
                "excludedSubtrees: [\(self.excludedSubtrees.map { String(reflecting: $0) }.joined(separator: ", "))]"
            )
        }

        return elements.joined(separator: ", ")
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "NameConstraints(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {

    @inlinable
    public init(_ nameConstraints: NameConstraints, critical: Bool) throws(ISO_8824.Error) {
        let asn1Representation = NameConstraintsValue(nameConstraints)
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.nameConstraints,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct NameConstraintsValue: ISO_8825.DER.ImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var permittedSubtrees: [GeneralName]?

    @usableFromInline
    var excludedSubtrees: [GeneralName]?

    @inlinable
    init(permittedSubtrees: [GeneralName]?, excludedSubtrees: [GeneralName]?) {
        self.permittedSubtrees = permittedSubtrees
        self.excludedSubtrees = excludedSubtrees
    }

    @inlinable
    init(_ ext: NameConstraints) {
        if !ext.permittedSubtrees.isEmpty {
            self.permittedSubtrees = ext.permittedSubtrees
        }
        if !ext.excludedSubtrees.isEmpty {
            self.excludedSubtrees = ext.excludedSubtrees
        }
    }

    @inlinable
    init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) {
            (
                nodes: inout ISO_8825.Node.Collection.Iterator
            ) throws(ISO_8824.Error) -> NameConstraintsValue in
            let permittedSubtrees: GeneralSubtrees? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 0, tagClass: .contextSpecific)
            )
            let excludedSubtrees: GeneralSubtrees? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )

            return NameConstraintsValue(
                permittedSubtrees: permittedSubtrees.map { $0.base },
                excludedSubtrees: excludedSubtrees.map { $0.base }
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
                permittedSubtrees.map { GeneralSubtrees($0) },
                withIdentifier: .init(tagWithNumber: 0, tagClass: .contextSpecific)
            )

            try coder.serializeOptionalImplicitlyTagged(
                excludedSubtrees.map { GeneralSubtrees($0) },
                withIdentifier: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )
        }
    }
}

@usableFromInline
struct GeneralSubtrees: ISO_8825.DER.ImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var base: [GeneralName]

    @inlinable
    init(_ base: [GeneralName]) {
        self.base = base
    }

    @inlinable
    init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self.base = try ISO_8825.DER.sequence(rootNode, identifier: identifier) {
            (
                nodes: inout ISO_8825.Node.Collection.Iterator
            ) throws(ISO_8824.Error)
                -> [GeneralName] in
            var names: [GeneralName] = []
            while let node = nodes.next() {
                let name = try ISO_8825.DER.sequence(node, identifier: .sequence) {
                    (
                        nodes: inout ISO_8825.Node.Collection.Iterator
                    ) throws(ISO_8824.Error) -> GeneralName in
                    try GeneralName(derEncoded: &nodes)
                }
                names.append(name)
            }
            return names
        }
    }

    @inlinable
    func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for name in base {
                try coder.appendConstructedNode(identifier: .sequence) {
                    (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    try coder.serialize(name)
                }
            }
        }
    }
}
