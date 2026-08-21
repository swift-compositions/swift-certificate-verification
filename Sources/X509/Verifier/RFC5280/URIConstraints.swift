import RFC_3986

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraintsPolicy {

    @inlinable
    package static func uriNameMatchesConstraint(uriName: String, constraint: String) -> Bool {

        let parsed: RFC_3986.URI
        do {
            parsed = try RFC_3986.URI(uriName)
        } catch {
            return false
        }
        guard let host = parsed.host else {
            return false
        }

        if host.ipv4Address != nil || host.ipv6Address != nil {

            return false
        }

        guard let regName = host.registeredNameValue else {
            return false
        }
        return Self.dnsNameMatchesConstraint(dnsName: regName.utf8, constraint: constraint.utf8)

    }
}
