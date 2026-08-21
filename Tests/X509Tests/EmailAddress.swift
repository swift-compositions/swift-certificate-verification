import ISO_8824

@testable import Certificates

public struct EmailAddress: RelativeDistinguishedNameConvertible, Sendable {

    public var name: String

    @inlinable
    public init(_ name: String) {
        self.name = name
    }

    @inlinable
    public func makeRDN() throws -> RelativeDistinguishedName {
        return RelativeDistinguishedName(
            try .init(type: .RDNAttributeType.emailAddress, ia5String: name)
        )
    }
}
