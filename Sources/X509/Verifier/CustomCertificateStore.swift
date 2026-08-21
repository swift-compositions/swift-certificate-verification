@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol CustomCertificateStore: Sendable, Hashable {

    subscript(subject: DistinguishedName) -> [Certificate]? {
        get async
    }

    func contains(_ certificate: Certificate) async -> Bool

    mutating func append(contentsOf certificates: some Sequence<Certificate>)
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
@usableFromInline
struct AnyCustomCertificateStore: CustomCertificateStore {
    @usableFromInline

    var value: any DynCustomCertificateStore

    @usableFromInline
    init<T: CustomCertificateStore>(_ value: T) {
        self.value = Backing(value)
    }

    @inlinable
    subscript(subject: DistinguishedName) -> [Certificate]? {
        get async {
            await value[subject]
        }
    }

    @inlinable
    func contains(_ certificate: Certificate) async -> Bool {
        await value.contains(certificate)
    }

    @inlinable
    mutating func append(contentsOf certificates: some Sequence<Certificate>) {
        value.append(contentsOf: certificates)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AnyCustomCertificateStore: Hashable {
    public static func == (lhs: AnyCustomCertificateStore, rhs: AnyCustomCertificateStore) -> Bool {
        return lhs.value.isEqual(rhs.value, recurse: true)
    }

    public func hash(into hasher: inout Hasher) {
        value.hash(into: &hasher)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AnyCustomCertificateStore {
    @usableFromInline
    protocol DynCustomCertificateStore: CustomCertificateStore {

        func isEqual(_ rhs: any DynCustomCertificateStore, recurse: Bool) -> Bool
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AnyCustomCertificateStore {
    struct Backing<T: CustomCertificateStore>: DynCustomCertificateStore {
        var value: T

        init(_ value: T) {
            self.value = value
        }

        subscript(subject: DistinguishedName) -> [Certificate]? {
            get async {
                await value[subject]
            }
        }

        func contains(_ certificate: Certificate) async -> Bool {
            await value.contains(certificate)
        }

        @inlinable
        mutating func append(contentsOf certificates: some Sequence<Certificate>) {
            value.append(contentsOf: certificates)
        }

        func isEqual(_ rhs: any DynCustomCertificateStore, recurse: Bool) -> Bool {
            guard let rhs = rhs as? Self else {
                guard recurse else {
                    return false
                }
                return rhs.isEqual(self, recurse: false)
            }
            return self == rhs
        }
    }
}
