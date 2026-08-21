@testable import Certificates

@resultBuilder
public struct DistinguishedNameBuilder: Sendable {
    @inlinable
    public static func buildExpression<Extension: RelativeDistinguishedNameConvertible>(
        _ expression: Extension
    ) -> Result<DistinguishedName, any Swift.Error> {
        Result {
            try DistinguishedName([expression.makeRDN()])
        }
    }

    @inlinable
    public static func buildBlock(
        _ components: Result<DistinguishedName, any Swift.Error>...
    ) -> Result<DistinguishedName, any Swift.Error> {
        Result {
            DistinguishedName(try components.flatMap { try $0.get() })
        }
    }

    @inlinable
    public static func buildOptional(
        _ component: Result<DistinguishedName, any Swift.Error>?
    ) -> Result<DistinguishedName, any Swift.Error> {
        component ?? .success(DistinguishedName())
    }

    @inlinable
    public static func buildEither(
        first component: Result<DistinguishedName, any Swift.Error>
    ) -> Result<DistinguishedName, any Swift.Error> {
        component
    }

    @inlinable
    public static func buildEither(
        second component: Result<DistinguishedName, any Swift.Error>
    ) -> Result<DistinguishedName, any Swift.Error> {
        component
    }

    @inlinable
    public static func buildArray(
        _ components: [Result<DistinguishedName, any Swift.Error>]
    ) -> Result<DistinguishedName, any Swift.Error> {
        Result {
            DistinguishedName(try components.flatMap { try $0.get() })
        }
    }

    @inlinable
    public static func buildLimitedAvailability(
        _ component: Result<DistinguishedName, any Swift.Error>
    ) -> Result<DistinguishedName, any Swift.Error> {
        component
    }
}

public protocol RelativeDistinguishedNameConvertible {
    func makeRDN() throws -> RelativeDistinguishedName
}
