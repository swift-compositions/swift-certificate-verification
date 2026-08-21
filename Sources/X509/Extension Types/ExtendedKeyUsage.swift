import ISO_8824
import ISO_8825

public struct ExtendedKeyUsage {
    @usableFromInline
    var usages: [Usage]

    @inlinable
    public init<Usages: Sequence>(_ usages: Usages) throws(Certificate.Error)
    where Usages.Element == Usage {
        self.usages = Array(usages)

        let maxUsages = 32
        guard self.usages.count <= maxUsages else {
            throw Certificate.Error.der(
                .invalidASN1Object(
                    reason:
                        "Too many extended key usages. Found \(self.usages.count) but only \(maxUsages) are allowed."
                )
            )
        }

        if let (firstIndex, _) = self.usages.findDuplicates(by: ==) {
            throw Certificate.Error.extension(
                .duplicateOID(ISO_8824.ObjectIdentifier(self.usages[firstIndex]))
            )
        }
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws(Certificate.Error) {
        guard ext.oid == .X509ExtensionID.extendedKeyUsage else {
            throw Certificate.Error.extension(
                .incorrectOID(expected: .X509ExtensionID.extendedKeyUsage, found: ext.oid)
            )
        }

        let asn1EKU: ASN1ExtendedKeyUsage
        do {
            asn1EKU = try ASN1ExtendedKeyUsage(derEncoded: ext.value)
        } catch {
            throw Certificate.Error.der(error)
        }
        try self.init(asn1EKU.usages.map { Usage(oid: $0) })
    }

    @inlinable
    public init() {
        self.usages = []
    }
}

extension Array {
    @inlinable

    package func findDuplicates(
        by areEqual: (Element, Element) -> Bool
    ) -> (first: Index, second: Index)? {
        for index in self.indices {
            let usage = self[index]
            for currentIndex in self.indices[index...].dropFirst() {
                let currentUsage = self[currentIndex]
                if areEqual(usage, currentUsage) {
                    return (index, currentIndex)
                }
            }
        }
        return nil
    }
}

extension ExtendedKeyUsage: Hashable {}

extension ExtendedKeyUsage: Sendable {}

extension ExtendedKeyUsage: CustomStringConvertible {
    public var description: String {
        return self.map {
            String(reflecting: $0)
        }.joined(separator: ", ")
    }
}

extension ExtendedKeyUsage: CustomDebugStringConvertible {
    public var debugDescription: String {
        "ExtendedKeyUsage(\(String(describing: self)))"
    }
}

extension ExtendedKeyUsage: RandomAccessCollection {
    public var startIndex: Int {
        self.usages.startIndex
    }

    public var endIndex: Int {
        self.usages.endIndex
    }

    public subscript(position: Int) -> Usage {
        self.usages[position]
    }
}

extension ExtendedKeyUsage {

    @inlinable
    @discardableResult
    public mutating func append(_ usage: Element) -> (inserted: Bool, index: Int) {
        self.insert(usage, at: self.endIndex)
    }

    @inlinable
    @discardableResult
    public mutating func insert(
        _ usage: Element,
        at index: Int
    ) -> (inserted: Bool, index: Int) {
        guard let index = self.usages.firstIndex(of: usage) else {
            self.usages.insert(usage, at: index)
            return (true, index)
        }
        return (false, index)
    }

    @inlinable
    @discardableResult
    public mutating func remove(_ usage: Element) -> Element? {
        guard let index = self.usages.firstIndex(where: { $0 == usage }) else {
            return nil
        }
        return self.usages.remove(at: index)
    }
}

extension ExtendedKeyUsage {

    public struct Usage {
        @usableFromInline
        enum Backing {
            case serverAuth
            case clientAuth
            case codeSigning
            case emailProtection
            case timeStamping
            case ocspSigning
            case any
            case certificateTransparency
            case unknown(ISO_8824.ObjectIdentifier)
        }

        @usableFromInline
        var backing: Backing

        @inlinable
        init(_ backing: Backing) {
            self.backing = backing
        }

        @inlinable
        public init(oid: ISO_8824.ObjectIdentifier) {
            switch oid {
            case .ExtendedKeyUsage.serverAuth:
                self = .serverAuth

            case .ExtendedKeyUsage.clientAuth:
                self = .clientAuth

            case .ExtendedKeyUsage.codeSigning:
                self = .codeSigning

            case .ExtendedKeyUsage.emailProtection:
                self = .emailProtection

            case .ExtendedKeyUsage.timeStamping:
                self = .timeStamping

            case .ExtendedKeyUsage.ocspSigning:
                self = .ocspSigning

            case .ExtendedKeyUsage.any:
                self = .any

            case .ExtendedKeyUsage.certificateTransparency:
                self = .certificateTransparency

            default:
                self.backing = .unknown(oid)
            }
        }

        public static let serverAuth = Self(.serverAuth)

        public static let clientAuth = Self(.clientAuth)

        public static let codeSigning = Self(.codeSigning)

        public static let emailProtection = Self(.emailProtection)

        public static let timeStamping = Self(.timeStamping)

        public static let ocspSigning = Self(.ocspSigning)

        public static let any = Self(.any)

        public static let certificateTransparency = Self(.certificateTransparency)
    }
}

extension ExtendedKeyUsage.Usage: Hashable {}

extension ExtendedKeyUsage.Usage: Sendable {}

extension ExtendedKeyUsage.Usage: CustomStringConvertible {
    public var description: String {
        switch self.backing {
        case .any:
            return "anyKeyUsage"

        case .serverAuth:
            return "serverAuth"

        case .clientAuth:
            return "clientAuth"

        case .codeSigning:
            return "codeSigning"

        case .emailProtection:
            return "emailProtection"

        case .timeStamping:
            return "timeStamping"

        case .ocspSigning:
            return "ocspSigning"

        case .certificateTransparency:
            return "certificateTransparency"

        case .unknown(let oid):
            return String(describing: oid)
        }
    }
}

extension ExtendedKeyUsage.Usage: CustomDebugStringConvertible {
    public var debugDescription: String {
        switch self.backing {
        case .any:
            return "anyKeyUsage"

        case .serverAuth:
            return "serverAuth"

        case .clientAuth:
            return "clientAuth"

        case .codeSigning:
            return "codeSigning"

        case .emailProtection:
            return "emailProtection"

        case .timeStamping:
            return "timeStamping"

        case .ocspSigning:
            return "ocspSigning"

        case .certificateTransparency:
            return "certificateTransparency"

        case .unknown(let oid):
            return String(reflecting: oid)
        }
    }
}

extension ExtendedKeyUsage.Usage.Backing: Hashable {}

extension ExtendedKeyUsage.Usage.Backing: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {

    @inlinable
    public init(_ eku: ExtendedKeyUsage, critical: Bool) throws(ISO_8824.Error) {
        let asn1Representation = ASN1ExtendedKeyUsage(eku)
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.extendedKeyUsage,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}

extension ISO_8824.ObjectIdentifier {

    @inlinable
    public init(_ usage: Certificates.ExtendedKeyUsage.Usage) {
        switch usage.backing {
        case .serverAuth:
            self = .ExtendedKeyUsage.serverAuth

        case .clientAuth:
            self = .ExtendedKeyUsage.clientAuth

        case .codeSigning:
            self = .ExtendedKeyUsage.codeSigning

        case .emailProtection:
            self = .ExtendedKeyUsage.emailProtection

        case .timeStamping:
            self = .ExtendedKeyUsage.timeStamping

        case .ocspSigning:
            self = .ExtendedKeyUsage.ocspSigning

        case .any:
            self = .ExtendedKeyUsage.any

        case .certificateTransparency:
            self = .ExtendedKeyUsage.certificateTransparency

        case .unknown(let oid):
            self = oid
        }
    }

    public enum ExtendedKeyUsage: Sendable {

        public static let any: ISO_8824.ObjectIdentifier = [2, 5, 29, 37, 0]

        public static let serverAuth: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 1]

        public static let clientAuth: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 2]

        public static let codeSigning: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 3]

        public static let emailProtection: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 4]

        public static let timeStamping: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 8]

        public static let ocspSigning: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 9]

        public static let certificateTransparency: ISO_8824.ObjectIdentifier = [
            1, 3, 6, 1, 4, 1, 11129, 2, 4, 4,
        ]
    }
}

@usableFromInline
struct ASN1ExtendedKeyUsage: ISO_8825.DER.ImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var usages: [ISO_8824.ObjectIdentifier]

    @inlinable
    init(_ usages: [ISO_8824.ObjectIdentifier]) {
        self.usages = usages
    }

    @inlinable
    init(_ eku: ExtendedKeyUsage) {
        self.usages = eku.usages.map { ISO_8824.ObjectIdentifier($0) }
    }

    @inlinable
    init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self.usages = try ISO_8825.DER.sequence(identifier: identifier, rootNode: rootNode)
    }

    @inlinable
    func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.serializeSequenceOf(self.usages, identifier: identifier)
    }
}
