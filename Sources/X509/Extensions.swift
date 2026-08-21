import ISO_8824
import ISO_8825
import Standard_Library_Extensions

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public struct Extensions {
        @usableFromInline
        var _extensions: [Certificate.Extension]

        @inlinable
        public init<Elements>(_ extensions: Elements) throws(Certificate.Error)
        where Elements: Sequence, Elements.Element == Extension {
            self._extensions = Array(extensions)

            let maxExtensions = 32
            guard self._extensions.count <= maxExtensions else {
                throw Certificate.Error.der(
                    .invalidASN1Object(
                        reason:
                            "Too many extensions. Found \(self._extensions.count) but only \(maxExtensions) are allowed."
                    )
                )
            }

            if let (firstIndex, _) = self._extensions.findDuplicates(by: { $0.oid == $1.oid }) {
                throw Certificate.Error.extension(.duplicateOID(self._extensions[firstIndex].oid))
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: RandomAccessCollection {

    @inlinable
    public init() {
        self._extensions = []
    }

    @inlinable
    public var startIndex: Int {
        self._extensions.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self._extensions.endIndex
    }

    @inlinable
    public subscript(position: Int) -> Certificate.Extension {
        self._extensions[position]
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions {

    @inlinable
    public mutating func append(_ extension: Certificate.Extension) throws(Certificate.Error) {
        if self._extensions.contains(where: { $0.oid == `extension`.oid }) {
            throw Certificate.Error.extension(.duplicateOID(`extension`.oid))
        } else {
            self._extensions.append(`extension`)
        }
    }

    @inlinable
    @discardableResult
    public mutating func update(_ extension: Certificate.Extension) -> Certificate.Extension? {
        guard let index = self._extensions.firstIndex(where: { $0.oid == `extension`.oid }) else {
            self._extensions.append(`extension`)
            return nil
        }
        let oldExtension = self._extensions[index]
        self._extensions[index] = `extension`
        return oldExtension
    }

    @inlinable
    @discardableResult
    public mutating func remove(_ oid: ISO_8824.ObjectIdentifier) -> Certificate.Extension? {
        guard let index = self._extensions.firstIndex(where: { $0.oid == oid }) else {
            return nil
        }
        return self._extensions.remove(at: index)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: CustomStringConvertible {
    @inlinable
    public var description: String {
        guard self.isEmpty else {
            return self._extensions.lazy.map { String(reflecting: $0) }.joined(separator: ", ")
        }
        return "(none)"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: CustomDebugStringConvertible {
    public var debugDescription: String {
        "[\(String(describing: self))]"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions {

    @inlinable
    public subscript(oid oid: ISO_8824.ObjectIdentifier) -> Certificate.Extension? {
        get {
            self._extensions.first(where: { $0.oid == oid })
        }
        set {
            if let newValue {
                precondition(oid == newValue.oid)
                self.update(newValue)
            } else {
                self.remove(oid)
            }
        }
    }

    @inlinable
    public var authorityInformationAccess: AuthorityInformationAccess? {
        get throws(Certificate.Error) {
            guard let ext = self[oid: .X509ExtensionID.authorityInformationAccess] else {
                return nil
            }
            return try .init(ext)
        }
    }

    @inlinable
    public var subjectKeyIdentifier: SubjectKeyIdentifier? {
        get throws(Certificate.Error) {
            guard let ext = self[oid: .X509ExtensionID.subjectKeyIdentifier] else { return nil }
            return try .init(ext)
        }
    }

    @inlinable
    public var authorityKeyIdentifier: AuthorityKeyIdentifier? {
        get throws(Certificate.Error) {
            guard let ext = self[oid: .X509ExtensionID.authorityKeyIdentifier] else { return nil }
            return try .init(ext)
        }
    }

    @inlinable
    public var extendedKeyUsage: ExtendedKeyUsage? {
        get throws(Certificate.Error) {
            guard let ext = self[oid: .X509ExtensionID.extendedKeyUsage] else { return nil }
            return try .init(ext)
        }
    }

    @inlinable
    public var basicConstraints: BasicConstraints? {
        get throws(Certificate.Error) {
            guard let ext = self[oid: .X509ExtensionID.basicConstraints] else { return nil }
            return try .init(ext)
        }
    }

    @inlinable
    public var keyUsage: KeyUsage? {
        get throws(Certificate.Error) {
            guard let ext = self[oid: .X509ExtensionID.keyUsage] else { return nil }
            return try .init(ext)
        }
    }

    @inlinable
    public var nameConstraints: NameConstraints? {
        get throws(Certificate.Error) {
            guard let ext = self[oid: .X509ExtensionID.nameConstraints] else { return nil }
            return try .init(ext)
        }
    }

    @inlinable
    public var subjectAlternativeNames: SubjectAlternativeNames? {
        get throws(Certificate.Error) {
            guard let ext = self[oid: .X509ExtensionID.subjectAlternativeName] else { return nil }
            return try .init(ext)
        }
    }
}
