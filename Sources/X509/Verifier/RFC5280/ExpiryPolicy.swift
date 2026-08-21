import ISO_8824
import ISO_8825
import Time_Primitive

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct ExpiryPolicy: VerifierPolicy, Sendable {
    @usableFromInline
    let verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] = []

    @usableFromInline
    let validationTime: ISO_8824.GeneralizedTime

    @inlinable
    init(validationTime: Instant) {
        self.validationTime = ISO_8824.GeneralizedTime(validationTime)
    }

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        let validationTime = self.validationTime

        for cert in chain {
            let notValidBefore = ISO_8824.GeneralizedTime(cert.tbsCertificate.validity.notBefore)
            let notValidAfter = ISO_8824.GeneralizedTime(cert.tbsCertificate.validity.notAfter)

            if notValidBefore > notValidAfter {
                return .failsToMeetPolicy(
                    reason:
                        "RFC5280Policy: Certificate \(cert) has invalid expiry, notValidAfter is earlier than notValidBefore"
                )
            }

            if validationTime < notValidBefore {
                return .failsToMeetPolicy(
                    reason: "RFC5280Policy: Certificate \(cert) is not yet valid"
                )
            }

            if validationTime > notValidAfter {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) has expired")
            }
        }

        return .meetsPolicy
    }
}
