import ISO_8824

@testable import Certificates

public struct StreetAddress: RelativeDistinguishedNameConvertible, Sendable {

    public var name: String

    @inlinable
    public init(_ name: String) {
        self.name = name
    }

    @inlinable
    public func makeRDN() throws -> RelativeDistinguishedName {
        return RelativeDistinguishedName(
            .init(type: .RDNAttributeType.streetAddress, utf8String: name)
        )
    }
}
