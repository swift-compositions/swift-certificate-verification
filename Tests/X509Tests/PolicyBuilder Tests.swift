import ISO_8824
import ISO_8825
import Testing
import Time_Primitive

@testable import Certificates

#if canImport(FoundationEssentials)
    import FoundationEssentials
#else
    import Foundation
#endif

private struct Policy: VerifierPolicy {
    var result: PolicyEvaluationResult = .meetsPolicy
    var verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] = []

    mutating func chainMeetsPolicyRequirements(
        chain: UnverifiedCertificateChain
    ) async -> PolicyEvaluationResult {
        result
    }
}

extension PolicyBuilder {
    @Suite struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
        @Suite struct Integration {}
    }
}

extension PolicyBuilder {

    fileprivate static let certificate = try! Fixture.certificate("root-ca")

    fileprivate static let chain = UnverifiedCertificateChain([
        certificate
    ])

    fileprivate static func assertMeetsPolicy(
        @PolicyBuilder makePolicy: () throws -> some VerifierPolicy,
        chain: UnverifiedCertificateChain? = nil,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async rethrows {
        var policy = try makePolicy()
        let result = await policy.chainMeetsPolicyRequirements(chain: chain ?? Self.chain)
        guard case .meetsPolicy = result else {
            Issue.record("\(result)", sourceLocation: sourceLocation)
            return
        }
    }

    fileprivate static func assertFailsToMeetPolicy(
        @PolicyBuilder makePolicy: () throws -> some VerifierPolicy,
        chain: UnverifiedCertificateChain? = nil,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async rethrows {
        var policy = try makePolicy()
        let result = await policy.chainMeetsPolicyRequirements(chain: chain ?? Self.chain)
        guard case .failsToMeetPolicy = result else {
            Issue.record("\(result)", sourceLocation: sourceLocation)
            return
        }
    }
}

extension PolicyBuilder.Test.Unit {
    @Test func `verifying critical extensions with concatenation`() {
        #expect(
            Set(
                AnyPolicy {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                }.verifyingCriticalExtensions
            ) == [
                [1, 1]
            ]
        )

        #expect(
            Set(
                AnyPolicy {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    Policy(verifyingCriticalExtensions: [[1, 2]])
                }.verifyingCriticalExtensions
            ) == [
                [1, 1],
                [1, 2],
            ]
        )

        #expect(
            Set(
                AnyPolicy {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    Policy(verifyingCriticalExtensions: [[1, 2]])
                    Policy(verifyingCriticalExtensions: [[1, 3]])
                }.verifyingCriticalExtensions
            ) == [
                [1, 1],
                [1, 2],
                [1, 3],
            ]
        )
    }

    @Test func `verifying critical extensions with if`() {
        let `true` = true
        let `false` = false
        #expect(
            Set(
                AnyPolicy {
                    if `true` {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                    }
                }.verifyingCriticalExtensions
            ) == [
                [1, 1]
            ]
        )

        #expect(
            Set(
                AnyPolicy {
                    if `false` {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                    }
                }.verifyingCriticalExtensions
            ) == []
        )
    }

    @Test func `verifying critical extensions with if else`() {
        let `true` = true
        let `false` = false
        #expect(
            Set(
                AnyPolicy {
                    if `true` {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                    } else {
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                    }
                }.verifyingCriticalExtensions
            ) == [
                [1, 1]
            ]
        )

        #expect(
            Set(
                AnyPolicy {
                    if `false` {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                    } else {
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                    }
                }.verifyingCriticalExtensions
            ) == [
                [1, 2]
            ]
        )
    }

    @Test func `chain meets policy requirements with concatenation`() async {
        await PolicyBuilder.assertMeetsPolicy {
            Policy(result: .meetsPolicy)
        }

        await PolicyBuilder.assertMeetsPolicy {
            Policy(result: .meetsPolicy)
            Policy(result: .meetsPolicy)
        }

        await PolicyBuilder.assertMeetsPolicy {
            Policy(result: .meetsPolicy)
            Policy(result: .meetsPolicy)
            Policy(result: .meetsPolicy)
        }

        await PolicyBuilder.assertFailsToMeetPolicy {
            Policy(result: .failsToMeetPolicy(reason: ""))
        }

        await PolicyBuilder.assertFailsToMeetPolicy {
            Policy(result: .meetsPolicy)
            Policy(result: .failsToMeetPolicy(reason: ""))
        }

        await PolicyBuilder.assertFailsToMeetPolicy {
            Policy(result: .failsToMeetPolicy(reason: ""))
            Policy(result: .meetsPolicy)
        }

        await PolicyBuilder.assertFailsToMeetPolicy {
            Policy(result: .meetsPolicy)
            Policy(result: .meetsPolicy)
            Policy(result: .failsToMeetPolicy(reason: ""))
        }
    }

    @Test func `chain meets policy requirements with if`() async {
        let `true` = true
        let `false` = false
        await PolicyBuilder.assertMeetsPolicy {
            if `true` {
                Policy(result: .meetsPolicy)
            }
        }

        await PolicyBuilder.assertMeetsPolicy {
            if `false` {
                Policy(result: .meetsPolicy)
            }
        }

        await PolicyBuilder.assertFailsToMeetPolicy {
            if `true` {
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }

        await PolicyBuilder.assertMeetsPolicy {
            if `false` {
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    @Test func `chain meets policy requirements with if else`() async {
        let `true` = true
        let `false` = false
        await PolicyBuilder.assertMeetsPolicy {
            if `true` {
                Policy(result: .meetsPolicy)
            } else {
                Policy(result: .meetsPolicy)
            }
        }

        await PolicyBuilder.assertMeetsPolicy {
            if `false` {
                Policy(result: .meetsPolicy)
            } else {
                Policy(result: .meetsPolicy)
            }
        }

        await PolicyBuilder.assertFailsToMeetPolicy {
            if `true` {
                Policy(result: .failsToMeetPolicy(reason: ""))
            } else {
                Policy(result: .meetsPolicy)
            }
        }

        await PolicyBuilder.assertMeetsPolicy {
            if `false` {
                Policy(result: .failsToMeetPolicy(reason: ""))
            } else {
                Policy(result: .meetsPolicy)
            }
        }

        await PolicyBuilder.assertMeetsPolicy {
            if `true` {
                Policy(result: .meetsPolicy)
            } else {
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }

        await PolicyBuilder.assertFailsToMeetPolicy {
            if `false` {
                Policy(result: .meetsPolicy)
            } else {
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    @Test func `any policy type is preserved`() {

        let _: Verifier<AnyPolicy> = Verifier(rootCertificates: CertificateStore(), verify: .crypto)
        {
            AnyPolicy {
                RFC5280Policy(validationTime: Instant(secondsSinceUnixEpoch: 1_767_225_600))
            }
        }
    }

    @Test func `all of policies non throwing`() {

        _ = AllOfPolicies {
            Policy(result: .meetsPolicy)
        }
    }

    @Test func `one of policies non throwing`() {

        _ = OneOfPolicies {
            Policy(result: .meetsPolicy)
        }
    }
}

extension PolicyBuilder.Test.`Edge Case` {
    @Test func `verifying critical extensions with empty builder`() {
        #expect(
            Set(
                AnyPolicy {

                }.verifyingCriticalExtensions
            ) == []
        )
    }

    @Test func `chain meets policy requirements with empty builder`() async {
        await PolicyBuilder.assertMeetsPolicy {

        }
    }

    @Test func `chain fails policy with one of empty`() async {
        await PolicyBuilder.assertFailsToMeetPolicy {
            OneOfPolicies {}
        }
        let `false` = false

        await PolicyBuilder.assertFailsToMeetPolicy {
            OneOfPolicies {
                if `false` {
                    Policy(result: .meetsPolicy)
                }
            }
        }

        let policy: Policy? = nil

        await PolicyBuilder.assertFailsToMeetPolicy {
            OneOfPolicies {
                if let policy {
                    policy
                }
            }
        }
    }

    @Test func `all of policies throwing`() {

        struct TestError: Swift.Error {}
        func throwingPolicyBuilder() throws -> Policy {
            throw TestError()
        }

        #expect(throws: TestError.self) {
            try AllOfPolicies {
                try throwingPolicyBuilder()
            }
        }
    }

    @Test func `one of policies throwing`() {

        struct TestError: Swift.Error {}
        func throwingPolicyBuilder() throws -> Policy {
            throw TestError()
        }

        #expect(throws: TestError.self) {
            try OneOfPolicies {
                try throwingPolicyBuilder()
            }
        }
    }
}

extension PolicyBuilder.Test.Integration {
    @Test func `verifying critical extensions with one of`() {

        #expect(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                }.verifyingCriticalExtensions
            ) == [
                [1, 1]
            ]
        )

        #expect(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1], [1, 2]])
                    Policy(verifyingCriticalExtensions: [[1, 2], [1, 3]])
                }.verifyingCriticalExtensions
            ) == [
                [1, 2]
            ]
        )

        #expect(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1], [1, 2]])
                    Policy(verifyingCriticalExtensions: [[1, 3], [1, 4]])
                }.verifyingCriticalExtensions
            ) == []
        )
    }

    @Test func `verifying critical extensions with one of and all of`() {

        #expect(
            Set(
                OneOfPolicies {
                    AllOfPolicies {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                    }
                }.verifyingCriticalExtensions
            ) == [
                [1, 1], [1, 2],
            ]
        )
        #expect(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    AllOfPolicies {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                    }
                }.verifyingCriticalExtensions
            ) == [
                [1, 1]
            ]
        )
        #expect(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    AllOfPolicies {
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                        Policy(verifyingCriticalExtensions: [[1, 3]])
                    }
                }.verifyingCriticalExtensions
            ) == []
        )
    }

    @Test func `chain meets policy with one of concatenation both valid`() async {
        await PolicyBuilder.assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .meetsPolicy)
            }
        }
    }

    @Test func `chain meets policy with one of concatenation first valid`() async {
        await PolicyBuilder.assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    @Test func `chain meets policy with one of concatenation second valid`() async {
        await PolicyBuilder.assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                Policy(result: .meetsPolicy)
            }
        }
    }

    @Test func `chain fails to meet policy with one of concatenation both invalid`() async {
        await PolicyBuilder.assertFailsToMeetPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    @Test func `chain meets policy requirements with one of if else`() async {
        let `true` = true
        let `false` = false
        await PolicyBuilder.assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                if `true` {
                    Policy(result: .meetsPolicy)
                } else {
                    Policy(result: .failsToMeetPolicy(reason: ""))
                }
            }
        }

        await PolicyBuilder.assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                if `false` {
                    Policy(result: .failsToMeetPolicy(reason: ""))
                } else {
                    Policy(result: .meetsPolicy)
                }
            }
        }

        await PolicyBuilder.assertFailsToMeetPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                if `true` {
                    Policy(result: .failsToMeetPolicy(reason: ""))
                } else {
                    Policy(result: .meetsPolicy)
                }
            }
        }
    }

    @Test func `chain meets policy requirements with one of optional`() async {
        let meeting: Policy? = Policy(result: .meetsPolicy)
        let failing: Policy? = Policy(result: .failsToMeetPolicy(reason: ""))
        await PolicyBuilder.assertMeetsPolicy {
            OneOfPolicies {
                if let meeting {
                    meeting
                }
            }
        }
        await PolicyBuilder.assertFailsToMeetPolicy {
            OneOfPolicies {
                if let failing {
                    failing
                }
            }
        }
    }

    @Test func `chain meets policy with all of`() async {
        await PolicyBuilder.assertMeetsPolicy {
            AllOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .meetsPolicy)
            }
        }
        await PolicyBuilder.assertFailsToMeetPolicy {
            AllOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    @Test func `chain meets policy with all of and one of`() async {
        await PolicyBuilder.assertMeetsPolicy {
            OneOfPolicies {
                AllOfPolicies {
                    Policy(result: .meetsPolicy)
                }
            }
        }
        await PolicyBuilder.assertFailsToMeetPolicy {
            OneOfPolicies {
                AllOfPolicies {
                    Policy(result: .failsToMeetPolicy(reason: ""))
                }
            }
        }
        await PolicyBuilder.assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .failsToMeetPolicy(reason: ""))
                AllOfPolicies {
                    Policy(result: .meetsPolicy)
                    Policy(result: .meetsPolicy)
                }
            }
        }
        await PolicyBuilder.assertFailsToMeetPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                AllOfPolicies {
                    Policy(result: .meetsPolicy)
                    Policy(result: .failsToMeetPolicy(reason: ""))
                }
            }
        }
    }
}
