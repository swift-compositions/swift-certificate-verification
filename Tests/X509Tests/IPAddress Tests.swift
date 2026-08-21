import Foundation
import ISO_8824
import ISO_8825
import Testing

@testable import Certificates

#if canImport(Android)
    import Android
#endif
#if canImport(WinSDK)
    import WinSDK
#endif

@Suite struct `IPAddress Tests` {
    static let fixtures: [(ISO_8824.OctetString, ISO_8824.OctetString, Bool)] = [

        (.v4("17.250.78.1"), .v4(subnet: "17.0.0.0", mask: "255.0.0.0"), true),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.0.66", mask: "255.255.0.0"), true),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.0", mask: "255.255.255.0"), true),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.255.255.255"), true),
        (.v4("18.250.78.1"), .v4(subnet: "17.0.0.0", mask: "255.0.0.0"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.2", mask: "255.255.255.255"), false),

        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "0.0.0.255"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "0.0.255.255"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "0.255.255.255"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.0.255.0"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.255.0.255"), false),

        (.v4("17.250.78.1"), .v4(subnet: "17.0.0.0", mask: "128.0.0.0"), true),
        (.v4("17.255.78.1"), .v4(subnet: "17.254.0.0", mask: "255.254.0.0"), true),
        (.v4("17.255.78.1"), .v4(subnet: "17.254.0.0", mask: "255.255.0.0"), false),

        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.255.62.0"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.239.255.255"), false),

        (.v4("17.250.78.1"), .v4(subnet: "0.0.0.0", mask: "0.0.0.0"), false),

        (.v4("17.250.78.1"), .v6(subnet: "8000::", mask: "8000::"), false),
        (.v6("fe80::"), .v4(subnet: "254.128.0.0", mask: "255.128.0.0"), false),

        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::", mask: "ffff:ffff:ffff:ffff::"), true),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:0:0:0", mask: "ffff:ffff:ffff:ffff:ffff::"), true
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:f7d:0:0", mask: "ffff:ffff:ffff:ffff:ffff:ffff::"), true
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:0", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:0"), true
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            true
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe81::", mask: "ffff:ffff:ffff:ffff::"),
            false
        ),
        (
            .v6("fe80::8d:f7d:79d5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            false
        ),

        (
            .v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "::ffff"),
            false
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "::ffff:ffff"), false
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "ffff::ffff"), false
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "ffff:0:0:ffff::ffff"), false
        ),

        (
            .v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "8000::"),
            true
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "fffe::"),
            true
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe81::8d:f7d:79c5:5719", mask: "ffff:ffff::"), false
        ),

        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe81::8d:f7d:79c5:5719", mask: "ffff:ffff:c9c9::"), false
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe81::8d:f7d:79c5:5719", mask: "ffff:ffff:feff:ffff:ffff:ffff:ffff:ffff"),
            false
        ),

        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "::", mask: "::"), false),

        (
            .v4("17.250.78.1"),
            ISO_8824.OctetString(contentBytes: .init(repeating: 0xff, count: 1)), false
        ),
        (
            .v4("17.250.78.1"),
            ISO_8824.OctetString(contentBytes: .init(repeating: 0xff, count: 7)), false
        ),
        (
            .v4("17.250.78.1"),
            ISO_8824.OctetString(contentBytes: .init(repeating: 0xff, count: 9)), false
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            ISO_8824.OctetString(contentBytes: .init(repeating: 0xff, count: 1)), false
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            ISO_8824.OctetString(contentBytes: .init(repeating: 0xff, count: 31)), false
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            ISO_8824.OctetString(contentBytes: .init(repeating: 0xff, count: 33)), false
        ),
    ]

    @Test func `constraints`() throws {

        for (presentedName, constraint, match) in Self.fixtures {
            #expect(
                NameConstraintsPolicy.ipAddressMatchesConstraint(
                    ipAddress: presentedName,
                    constraint: constraint
                )
                    == match
            )
        }
    }
}

extension ISO_8824.OctetString {
    static func v4(_ ipv4Address: String) -> ISO_8824.OctetString {
        var addr = in_addr()
        let rc = inet_pton(AF_INET, ipv4Address, &addr)
        precondition(rc == 1)

        let bytes = Swift.withUnsafeBytes(of: &addr) {
            ArraySlice($0)
        }

        return .init(contentBytes: bytes)
    }

    static func v6(_ ipv6Address: String) -> ISO_8824.OctetString {
        var addr = in6_addr()
        let rc = inet_pton(AF_INET6, ipv6Address, &addr)
        precondition(rc == 1)

        let bytes = Swift.withUnsafeBytes(of: &addr) {
            ArraySlice($0)
        }

        return .init(contentBytes: bytes)
    }

    static func v4(subnet: String, mask: String) -> ISO_8824.OctetString {
        let subnet = ISO_8824.OctetString.v4(subnet)
        let mask = ISO_8824.OctetString.v4(mask)
        return ISO_8824.OctetString(contentBytes: subnet.bytes + mask.bytes)
    }

    static func v6(subnet: String, mask: String) -> ISO_8824.OctetString {
        let subnet = ISO_8824.OctetString.v6(subnet)
        let mask = ISO_8824.OctetString.v6(mask)
        return ISO_8824.OctetString(contentBytes: subnet.bytes + mask.bytes)
    }
}
