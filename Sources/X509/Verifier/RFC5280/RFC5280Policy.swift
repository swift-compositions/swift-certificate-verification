import ISO_8824
import ISO_8825
import Time_Primitive

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct RFC5280Policy: VerifierPolicy, Sendable {
    public let verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints,
        .X509ExtensionID.nameConstraints,

        .X509ExtensionID.keyUsage,
    ]

    @usableFromInline
    let versionPolicy: VersionPolicy

    @usableFromInline
    let expiryPolicy: ExpiryPolicy

    @usableFromInline
    let basicConstraintsPolicy: BasicConstraintsPolicy

    @usableFromInline
    let nameConstraintsPolicy: NameConstraintsPolicy

    @inlinable
    public init(validationTime: Instant) {
        self.versionPolicy = VersionPolicy()
        self.expiryPolicy = ExpiryPolicy(validationTime: validationTime)
        self.basicConstraintsPolicy = BasicConstraintsPolicy()
        self.nameConstraintsPolicy = NameConstraintsPolicy()
    }

    @inlinable
    public func chainMeetsPolicyRequirements(
        chain: UnverifiedCertificateChain
    ) -> PolicyEvaluationResult {
        if case .failsToMeetPolicy(let reason) = self.versionPolicy.chainMeetsPolicyRequirements(
            chain: chain
        ) {
            return .failsToMeetPolicy(reason: reason)
        }
        if case .failsToMeetPolicy(let reason) = self.expiryPolicy.chainMeetsPolicyRequirements(
            chain: chain
        ) {
            return .failsToMeetPolicy(reason: reason)
        }

        if case .failsToMeetPolicy(let reason) = self.basicConstraintsPolicy
            .chainMeetsPolicyRequirements(chain: chain)
        {
            return .failsToMeetPolicy(reason: reason)
        }

        if case .failsToMeetPolicy(let reason) = self.nameConstraintsPolicy
            .chainMeetsPolicyRequirements(chain: chain)
        {
            return .failsToMeetPolicy(reason: reason)
        }

        return .meetsPolicy
    }
}
