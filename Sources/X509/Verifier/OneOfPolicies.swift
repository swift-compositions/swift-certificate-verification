import ISO_8824
import ISO_8825

@resultBuilder
public struct OneOfPolicyBuilder: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OneOfPolicyBuilder {
    @inlinable
    public static func buildLimitedAvailability<Policy: VerifierPolicy>(
        _ component: Policy
    ) -> Policy {
        component
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OneOfPolicyBuilder {
    @usableFromInline
    struct Empty: VerifierPolicy, Sendable {
        @inlinable
        var verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] { [] }

        @inlinable
        init() {}

        @inlinable
        mutating func chainMeetsPolicyRequirements(
            chain: UnverifiedCertificateChain
        ) async -> PolicyEvaluationResult {
            .failsToMeetPolicy(reason: "No policies specified in OneOfPolicies block")
        }
    }

    @inlinable
    public static func buildBlock() -> some VerifierPolicy {
        Empty()
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OneOfPolicyBuilder {
    @usableFromInline
    struct Tuple2<First: VerifierPolicy, Second: VerifierPolicy>: VerifierPolicy {
        @usableFromInline
        var first: First

        @usableFromInline
        var second: Second

        @inlinable
        init(first: First, second: Second) {
            self.first = first
            self.second = second
        }

        @inlinable
        var verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] {
            let firstExtensions = first.verifyingCriticalExtensions
            let secondExtensions = second.verifyingCriticalExtensions
            return firstExtensions.filter { secondExtensions.contains($0) }
        }

        @inlinable
        mutating func chainMeetsPolicyRequirements(
            chain: UnverifiedCertificateChain
        ) async -> PolicyEvaluationResult {
            let firstResult = await self.first.chainMeetsPolicyRequirements(chain: chain)
            switch firstResult {
            case .meetsPolicy:
                return .meetsPolicy

            case .failsToMeetPolicy(let firstReason):
                let secondResult = await self.second.chainMeetsPolicyRequirements(chain: chain)
                switch secondResult {
                case .meetsPolicy:
                    return .meetsPolicy

                case .failsToMeetPolicy(let secondReason):
                    return .failsToMeetPolicy(reason: "\(firstReason) and \(secondReason)")
                }
            }
        }
    }

    @inlinable
    public static func buildPartialBlock<Policy: VerifierPolicy>(first: Policy) -> Policy {
        first
    }

    @inlinable
    public static func buildPartialBlock(
        accumulated: some VerifierPolicy,
        next: some VerifierPolicy
    ) -> some VerifierPolicy {
        Tuple2(first: accumulated, second: next)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OneOfPolicyBuilder.Tuple2: Sendable where First: Sendable, Second: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OneOfPolicyBuilder {
    @usableFromInline
    struct WrappedOptional<Wrapped>: VerifierPolicy where Wrapped: VerifierPolicy {
        @usableFromInline
        var wrapped: Wrapped?

        @inlinable
        init(_ wrapped: Wrapped?) {
            self.wrapped = wrapped
        }

        @inlinable
        var verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] {
            self.wrapped?.verifyingCriticalExtensions ?? []
        }

        @inlinable
        mutating func chainMeetsPolicyRequirements(
            chain: UnverifiedCertificateChain
        ) async -> PolicyEvaluationResult {
            await self.wrapped?.chainMeetsPolicyRequirements(chain: chain)
                ?? .failsToMeetPolicy(reason: "\(Wrapped.self) in OneOfPolicy is disabled")
        }
    }

    @inlinable
    public static func buildOptional(_ component: (some VerifierPolicy)?) -> some VerifierPolicy {
        WrappedOptional(component)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OneOfPolicyBuilder.WrappedOptional: Sendable where Wrapped: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OneOfPolicyBuilder {
    @inlinable
    public static func buildEither<First: VerifierPolicy, Second: VerifierPolicy>(
        first component: First
    ) -> PolicyBuilder._Either<First, Second> {
        PolicyBuilder._Either<First, Second>(storage: .first(component))
    }

    @inlinable
    public static func buildEither<First: VerifierPolicy, Second: VerifierPolicy>(
        second component: Second
    ) -> PolicyBuilder._Either<First, Second> {
        PolicyBuilder._Either<First, Second>(storage: .second(component))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct OneOfPolicies<Policy: VerifierPolicy>: VerifierPolicy {
    @usableFromInline
    var policy: Policy

    @inlinable
    public init(@OneOfPolicyBuilder policy: () throws -> Policy) throws {
        self.policy = try policy()
    }

    @inlinable
    public init(@OneOfPolicyBuilder policy: () -> Policy) {
        self.policy = policy()
    }

    @inlinable
    public var verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] {
        policy.verifyingCriticalExtensions
    }

    @inlinable
    public mutating func chainMeetsPolicyRequirements(
        chain: UnverifiedCertificateChain
    ) async -> PolicyEvaluationResult {
        await self.policy.chainMeetsPolicyRequirements(chain: chain)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OneOfPolicies: Sendable where Policy: Sendable {}
