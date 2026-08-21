import ISO_8824
import ISO_8825

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct VersionPolicy: VerifierPolicy, Sendable {
    @inlinable
    var verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] { [] }

    @inlinable
    init() {}

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        for certificate in chain {
            if certificate.version == .v1 && certificate.extensions.isEmpty == false {
                return .failsToMeetPolicy(
                    reason:
                        "version 1 certificate contains extensions but should not: \(certificate)"
                )
            }
        }
        return .meetsPolicy
    }
}
