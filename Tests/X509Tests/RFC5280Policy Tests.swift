@preconcurrency import Crypto
import ISO_8824
import ISO_8825
import Testing

@testable @_spi(DisableValidityCheck) @_spi(FixedExpiryValidationTime) import Certificates

#if canImport(FoundationEssentials)
    import FoundationEssentials
#else
    import Foundation
#endif

extension RFC5280Policy {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
        @Suite struct Integration {}

    }
}

extension RFC5280Policy.Test.Unit {
    @Test
    func `ignores key usage`() async throws {

        let alternativeIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )

                Critical(
                    KeyUsage(digitalSignature: true)
                )
            },
            issuer: .unconstrainedRoot
        )

        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy() }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([alternativeIntermediate])
        )

        guard case .validCertificate(let chain) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(Array(chain) == [leaf, alternativeIntermediate, TestPKI.unconstrainedCA])
    }
}

extension RFC5280Policy.Test.`Edge Case` {
    @Test
    func `valid v1 certs with extensions are rejected`() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            version: .v1,
            issuer: .unconstrainedIntermediate,
            customExtensions: try .init {
                Certificate.Extension(oid: [1, 2, 3, 4], critical: false, value: [5, 6, 7, 8])
            }
        )

        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy() }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate(let policyFailures) = result else {
            Issue.record("Validated: \(result)")
            return
        }

        #expect(policyFailures.count == 1)
    }

    @Test
    func `expired leaf is rejected`() async throws {
        try await Test._expiredLeafIsRejected(.rfc5280)
    }

    @Test
    func `expired leaf is rejected base policy`() async throws {
        try await Test._expiredLeafIsRejected(.expiry)
    }

    @Test
    func `expired leaf is not rejected if the policy disables expiry checking`() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 1.0,
            notValidAfter: TestPKI.startDate + 2.0,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy.withValidityCheckDisabled()
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }
    }

    @Test
    func `expiry check correct when delay between initialization and validation`() async throws {
        let currentTime = Date()

        let leaf = TestPKI.issueLeaf(
            notValidBefore: currentTime,
            notValidAfter: currentTime + 1,
            issuer: .unconstrainedIntermediate
        )

        let timeAtInitPolicy = RFC5280Policy(fixedExpiryValidationTime: .now)

        let timeAtValidationPolicy = RFC5280Policy()

        try await Task.sleep(for: .seconds(2))

        var timeAtInitVerifier = Verifier(
            rootCertificates: CertificateStore([TestPKI.unconstrainedCA])
        ) {
            timeAtInitPolicy
        }
        var timeAtValidationVerifier = Verifier(
            rootCertificates: CertificateStore([TestPKI.unconstrainedCA])
        ) {
            timeAtValidationPolicy
        }

        let timeAtInitResult = await timeAtInitVerifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )
        let timeAtValidationResult = await timeAtValidationVerifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate = timeAtInitResult else {
            Issue.record(
                "validation time < certificate expiration, but the certificate was determined to be invalid."
            )
            return
        }

        guard case .couldNotValidate(let policyFailures) = timeAtValidationResult else {
            Issue.record("An expired certificate was incorrectly determined to be valid.")
            return
        }
        #expect(policyFailures.count == 1)
    }

    @Test
    func `expired intermediate is rejected`() async throws {
        try await Test._expiredIntermediateIsRejected(.rfc5280)
    }

    @Test
    func `expired intermediate is rejected base policy`() async throws {
        try await Test._expiredIntermediateIsRejected(.expiry)
    }

    @Test
    func `expired intermediate is not rejected if the policy disables expiry checking`()
        async throws
    {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,

            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter + 2.0,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy.withValidityCheckDisabled()
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }
    }

    @Test
    func `expired root is rejected`() async throws {
        try await Test._expiredRootIsRejected(.rfc5280)
    }

    @Test
    func `expired root is rejected base policy`() async throws {
        try await Test._expiredRootIsRejected(.expiry)
    }

    @Test
    func `expired root is not rejected if the policy disables expiry checking`() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,
            notValidAfter: TestPKI.unconstrainedCA.notValidAfter + 2.0,

            issuer: .unconstrainedRoot
        )

        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy.withValidityCheckDisabled()
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }
    }

    @Test
    func `not yet valid leaf is rejected`() async throws {
        try await Test._notYetValidLeafIsRejected(.rfc5280)
    }

    @Test
    func `not yet valid leaf is rejected base policy`() async throws {
        try await Test._notYetValidLeafIsRejected(.expiry)
    }

    @Test
    func `not yet valid leaf is not rejected if validity checking is disabled`() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 2.0,
            notValidAfter: TestPKI.startDate + 3.0,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy.withValidityCheckDisabled()
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }
    }

    @Test
    func `not yet valid intermediate is rejected`() async throws {
        try await Test._notYetValidIntermediateIsRejected(.rfc5280)
    }

    @Test
    func `not yet valid intermediate is rejected base policy`() async throws {
        try await Test._notYetValidIntermediateIsRejected(.expiry)
    }

    @Test
    func `not yet valid intermediate is not rejected if validity checking is disabled`()
        async throws
    {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(

            notValidBefore: TestPKI.unconstrainedIntermediate.notValidBefore - 2.0,
            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy.withValidityCheckDisabled()
        }

        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }
    }

    @Test
    func `not yet valid root is rejected`() async throws {
        try await Test._notYetValidRootIsRejected(.rfc5280)
    }

    @Test
    func `not yet valid root is rejected base policy`() async throws {
        try await Test._notYetValidRootIsRejected(.expiry)
    }

    @Test
    func `not yet valid root is not rejected if validity checking is disabled`() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.unconstrainedCA.notValidBefore - 2.0,
            notValidAfter: TestPKI.startDate,

            issuer: .unconstrainedRoot
        )

        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy.withValidityCheckDisabled()
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }
    }

    @Test
    func `malformed expiry is rejected`() async throws {
        try await Test._malformedExpiryIsRejected(.rfc5280)
    }

    @Test
    func `malformed expiry is rejected base policy`() async throws {
        try await Test._malformedExpiryIsRejected(.expiry)
    }

    @Test
    func `malformed expiry is not rejected if validity checking is disabled`() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 3.0,
            notValidAfter: TestPKI.startDate + 2.0,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy.withValidityCheckDisabled()
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }
    }

    @Test
    func `self signed certs must be marked as ca`() async throws {
        try await Test._selfSignedCertsMustBeMarkedAsCA(.rfc5280)
    }

    @Test
    func `self signed certs must be marked as ca base policy`() async throws {
        try await Test._selfSignedCertsMustBeMarkedAsCA(.basicConstraints)
    }

    @Test
    func `intermediate ca must be marked as ca in basic constraints`() async throws {
        try await Test._intermediateCAMustBeMarkedCAInBasicConstraints(.rfc5280)
    }

    @Test
    func `intermediate ca must be marked as ca in basic constraints base policy`() async throws {
        try await Test._intermediateCAMustBeMarkedCAInBasicConstraints(.basicConstraints)
    }

    @Test
    func `root ca must be marked as ca in basic constraints`() async throws {
        try await Test._rootCAMustBeMarkedCAInBasicConstraints(.rfc5280)
    }

    @Test
    func `root ca must be marked as ca in basic constraints base policy`() async throws {
        try await Test._rootCAMustBeMarkedCAInBasicConstraints(.basicConstraints)
    }

    @Test
    func `path length constraints from intermediates are applied`() async throws {
        try await Test._pathLengthConstraintsFromIntermediatesAreApplied(.rfc5280)
    }

    @Test
    func `path length constraints from intermediates are applied base policy`() async throws {
        try await Test._pathLengthConstraintsFromIntermediatesAreApplied(.basicConstraints)
    }

    @Test
    func `path length constraints on roots are applied`() async throws {
        try await Test._pathLengthConstraintsFromIntermediatesAreApplied(.rfc5280)
    }

    @Test
    func `path length constraints on roots are applied base policy`() async throws {
        try await Test._pathLengthConstraintsFromIntermediatesAreApplied(.basicConstraints)
    }

    @Test
    func `path length constraints does only count non self issued certificates`() async throws {
        try await Test._pathLengthConstraintsDoesOnlyCountNonSelfIssuedCertificates(.rfc5280)
    }

    @Test
    func `path length constraints does only count non self issued certificates base policy`()
        async throws
    {
        try await Test._pathLengthConstraintsDoesOnlyCountNonSelfIssuedCertificates(
            .basicConstraints
        )
    }

    @Test
    func `subtrees of unknown type always fail`() async throws {
        try await Test.subtreesOfUnknownTypeAlwaysFail(.rfc5280)
    }

    @Test
    func `subtrees of unknown type always fail base policy`() async throws {
        try await Test.subtreesOfUnknownTypeAlwaysFail(.nameConstraints)
    }

    @Test
    func `broken extensions prevent validation`() async throws {
        try await Test.brokenExtensionsPreventValidation(.rfc5280)
    }

    @Test
    func `broken extensions prevent validation base policy`() async throws {
        try await Test.brokenExtensionsPreventValidation(.nameConstraints)
    }

    @Test
    func `excluded subtrees beat permitted subtrees`() async throws {
        try await Test.excludedSubtreesBeatPermittedSubtrees(.rfc5280)
    }

    @Test
    func `excluded subtrees beat permitted subtrees base policy`() async throws {
        try await Test.excludedSubtreesBeatPermittedSubtrees(.nameConstraints)
    }

    @Test
    func `fails on weird critical extension in leaf`() async throws {

        let leaf = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate,

            customExtensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                Certificate.Extension(
                    oid: [1, 2, 3, 4, 5],
                    critical: true,
                    value: [1, 2, 3, 4, 5]
                )
            }
        )

        let roots = CertificateStore([TestPKI.unconstrainedCA])

        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy() }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate = result else {
            Issue.record("Incorrectly validated: \(result)")
            return
        }
    }
}

extension RFC5280Policy.Test.Integration {
    @Test
    func `valid certs are accepted`() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy() }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate(let chain) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(Array(chain) == [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA])
    }

    @Test
    func `valid v1 certs are accepted`() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            version: .v1,
            issuer: .unconstrainedIntermediate,
            customExtensions: .init()
        )

        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy() }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate(let chain) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(Array(chain) == [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA])
    }

    @Test
    func `dns name constraints excluded subtrees`() async throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            try await Test.nameconstraintsExcludedSubtrees(
                excludedSubtrees: [.dnsName(constraint)],
                subjectAlternativeNames: [.dnsName(dnsName)],
                match: match,
                policyFactory: .rfc5280
            )
        }
    }

    @Test
    func `dns name constraints excluded subtrees base policy`() async throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            try await Test.nameconstraintsExcludedSubtrees(
                excludedSubtrees: [.dnsName(constraint)],
                subjectAlternativeNames: [.dnsName(dnsName)],
                match: match,
                policyFactory: .nameConstraints
            )
        }
    }

    @Test
    func `ip address name constraints excluded subtrees`() async throws {
        for (ipAddress, constraint, match) in IPAddressNameTests.fixtures {
            try await Test.nameconstraintsExcludedSubtrees(
                excludedSubtrees: [.ipAddress(constraint)],
                subjectAlternativeNames: [.ipAddress(ipAddress)],
                match: match,
                policyFactory: .rfc5280
            )
        }
    }

    @Test
    func `ip address name constraints excluded subtrees base policy`() async throws {
        for (ipAddress, constraint, match) in IPAddressNameTests.fixtures {
            try await Test.nameconstraintsExcludedSubtrees(
                excludedSubtrees: [.ipAddress(constraint)],
                subjectAlternativeNames: [.ipAddress(ipAddress)],
                match: match,
                policyFactory: .nameConstraints
            )
        }
    }

    @Test
    func `directory name constraints excluded subtrees`() async throws {
        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                try await Test.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.directoryName(firstName)],
                    subjectAlternativeNames: [.directoryName(secondName)],
                    match: firstName == secondName,
                    policyFactory: .rfc5280
                )
            }
        }
    }

    @Test
    func `directory name constraints excluded subtrees base policy`() async throws {
        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                try await Test.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.directoryName(firstName)],
                    subjectAlternativeNames: [.directoryName(secondName)],
                    match: firstName == secondName,
                    policyFactory: .nameConstraints
                )
            }
        }
    }

    @Test
    func `dns name constraints permitted subtrees`() async throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            try await Test.nameconstraintsPermittedSubtrees(
                permittedSubtrees: [.dnsName(constraint)],
                subjectAlternativeNames: [.dnsName(dnsName)],
                match: match,
                policyFactory: .rfc5280
            )
        }
    }

    @Test
    func `dns name constraints permitted subtrees base policy`() async throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            try await Test.nameconstraintsPermittedSubtrees(
                permittedSubtrees: [.dnsName(constraint)],
                subjectAlternativeNames: [.dnsName(dnsName)],
                match: match,
                policyFactory: .nameConstraints
            )
        }
    }

    @Test
    func `ip address name constraints permitted subtrees`() async throws {
        for (ipAddress, constraint, match) in IPAddressNameTests.fixtures {
            try await Test.nameconstraintsPermittedSubtrees(
                permittedSubtrees: [.ipAddress(constraint)],
                subjectAlternativeNames: [.ipAddress(ipAddress)],
                match: match,
                policyFactory: .rfc5280
            )
        }
    }

    @Test
    func `ip address name constraints permitted subtrees base policy`() async throws {
        for (ipAddress, constraint, match) in IPAddressNameTests.fixtures {
            try await Test.nameconstraintsPermittedSubtrees(
                permittedSubtrees: [.ipAddress(constraint)],
                subjectAlternativeNames: [.ipAddress(ipAddress)],
                match: match,
                policyFactory: .nameConstraints
            )
        }
    }

    @Test
    func `directory name constraints permitted subtrees`() async throws {

        let leafName = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Leaf")
        }

        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                try await Test.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [
                        .directoryName(firstName),
                        .directoryName(TestPKI.unconstrainedIntermediateName),
                        .directoryName(leafName),
                    ],
                    subjectAlternativeNames: [.directoryName(secondName)],
                    match: firstName == secondName,
                    policyFactory: .rfc5280
                )
            }
        }
    }

    @Test
    func `directory name constraints permitted subtrees base policy`() async throws {

        let leafName = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Leaf")
        }

        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                try await Test.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [
                        .directoryName(firstName),
                        .directoryName(TestPKI.unconstrainedIntermediateName),
                        .directoryName(leafName),
                    ],
                    subjectAlternativeNames: [.directoryName(secondName)],
                    match: firstName == secondName,
                    policyFactory: .nameConstraints
                )
            }
        }
    }

    @Test
    func `all excluded subtrees are evaluated`() async throws {
        try await Test.allExcludedSubtreesAreEvaluated(.rfc5280)
    }

    @Test
    func `all excluded subtrees are evaluated base policy`() async throws {
        try await Test.allExcludedSubtreesAreEvaluated(.nameConstraints)
    }

    @Test
    func `uri name constraints excluded subtrees`() async throws {

        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                try await Test.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(constraint)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(uri)],
                    match: match,
                    policyFactory: .rfc5280
                )

                try await Test.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(uri)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(constraint)],
                    match: false,
                    policyFactory: .rfc5280
                )
            }

            if constraint.isEmpty {

                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                try await Test.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(constraint)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(uri)],
                    match: false,
                    policyFactory: .rfc5280
                )
            }
        }
    }

    @Test
    func `uri name constraints excluded subtrees base policy`() async throws {

        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                try await Test.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(constraint)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(uri)],
                    match: match,
                    policyFactory: .nameConstraints
                )

                try await Test.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(uri)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(constraint)],
                    match: false,
                    policyFactory: .nameConstraints
                )
            }

            if constraint.isEmpty {

                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                try await Test.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(constraint)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(uri)],
                    match: false,
                    policyFactory: .nameConstraints
                )
            }
        }
    }

    @Test
    func `uri name constraints permitted subtrees`() async throws {

        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                try await Test.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(constraint)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(uri)],
                    match: match,
                    policyFactory: .rfc5280
                )

                try await Test.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(uri)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(constraint)],
                    match: false,
                    policyFactory: .rfc5280
                )
            }

            if constraint.isEmpty {

                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                try await Test.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(constraint)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(uri)],
                    match: false,
                    policyFactory: .rfc5280
                )
            }
        }
    }

    @Test
    func `uri name constraints permitted subtrees base policy`() async throws {

        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                try await Test.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(constraint)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(uri)],
                    match: match,
                    policyFactory: .nameConstraints
                )

                try await Test.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(uri)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(constraint)],
                    match: false,
                    policyFactory: .nameConstraints
                )
            }

            if constraint.isEmpty {

                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                try await Test.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(constraint)],
                    subjectAlternativeNames: [.uniformResourceIdentifier(uri)],
                    match: false,
                    policyFactory: .nameConstraints
                )
            }
        }
    }
}

extension RFC5280Policy.Test {
    enum PolicyFactory {
        case rfc5280
        case expiry
        case basicConstraints
        case nameConstraints

        @PolicyBuilder
        func create(_ fixedValidationTime: Date) -> some VerifierPolicy {
            switch self {
            case .rfc5280:
                RFC5280Policy(fixedExpiryValidationTime: fixedValidationTime)

            case .expiry:
                ExpiryPolicy(fixedValidationTime: fixedValidationTime)
                CatchAllPolicy()

            case .basicConstraints:
                BasicConstraintsPolicy()
                CatchAllPolicy()

            case .nameConstraints:
                NameConstraintsPolicy()
                CatchAllPolicy()

            }
        }

        struct CatchAllPolicy: VerifierPolicy {
            let verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] = [
                .X509ExtensionID.basicConstraints,
                .X509ExtensionID.nameConstraints,
                .X509ExtensionID.keyUsage,
            ]

            func chainMeetsPolicyRequirements(
                chain: UnverifiedCertificateChain
            ) async -> PolicyEvaluationResult {
                return .meetsPolicy
            }
        }
    }

    static func nameconstraintsExcludedSubtrees(
        excludedSubtrees: [GeneralName],
        subjectAlternativeNames: [GeneralName],
        match: Bool,
        policyFactory: PolicyFactory
    ) async throws {
        let alternativeRoot = TestPKI.issueCA(

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    NameConstraints(excludedSubtrees: excludedSubtrees)
                )
            }
        )

        let alternativeIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
                Critical(
                    NameConstraints(excludedSubtrees: excludedSubtrees)
                )
            },
            issuer: .unconstrainedRoot
        )

        let intermediateWithAConstrainedNameForSomeReason = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
                SubjectAlternativeNames(subjectAlternativeNames)
            },
            issuer: .unconstrainedRoot
        )

        let leaf = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate,
            subjectAlternativeNames: subjectAlternativeNames
        )
        let leafWithoutNames = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate
        )

        var roots = CertificateStore([alternativeRoot])
        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        var result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        switch (match, result) {
        case (true, .couldNotValidate), (false, .validCertificate):

            ()

        default:
            Issue.record(
                "Incorrect validation on excluded subtrees \(excludedSubtrees) for \(subjectAlternativeNames) from root, expected \(match) got \(result)"
            )
        }

        roots = CertificateStore([TestPKI.unconstrainedCA])
        verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([alternativeIntermediate])
        )

        switch (match, result) {
        case (true, .couldNotValidate), (false, .validCertificate):

            ()

        default:
            Issue.record(
                "Incorrect validation on excluded subtrees \(excludedSubtrees) for \(subjectAlternativeNames) from intermediate, expected \(match) got \(result)"
            )
        }

        roots = CertificateStore([alternativeRoot])
        verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        result = await verifier.validate(
            leaf: leafWithoutNames,
            intermediates: CertificateStore([intermediateWithAConstrainedNameForSomeReason])
        )

        switch (match, result) {
        case (true, .couldNotValidate), (false, .validCertificate):

            ()

        default:
            Issue.record(
                "Incorrect validation on excluded subtrees \(excludedSubtrees) for \(subjectAlternativeNames) from intermediate, expected \(match) got \(result)"
            )
        }

        roots = CertificateStore([TestPKI.unconstrainedCA])
        verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([intermediateWithAConstrainedNameForSomeReason])
        )

        guard case .validCertificate(let chain) = result else {
            Issue.record("Unable to validate with unconstrained root: \(result)")
            return
        }

        #expect(
            Array(chain) == [
                leaf, intermediateWithAConstrainedNameForSomeReason, TestPKI.unconstrainedCA,
            ]
        )
    }

    static func nameconstraintsPermittedSubtrees(
        permittedSubtrees: [GeneralName],
        subjectAlternativeNames: [GeneralName],
        match: Bool,
        policyFactory: PolicyFactory
    ) async throws {
        let alternativeRoot = TestPKI.issueCA(

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    NameConstraints(permittedSubtrees: permittedSubtrees)
                )
            }
        )

        let alternativeIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
                Critical(
                    NameConstraints(permittedSubtrees: permittedSubtrees)
                )
            },
            issuer: .unconstrainedRoot
        )

        let intermediateWithAConstrainedNameForSomeReason = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
                SubjectAlternativeNames(subjectAlternativeNames)
            },
            issuer: .unconstrainedRoot
        )

        let leaf = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate,
            subjectAlternativeNames: subjectAlternativeNames
        )
        let leafWithoutNames = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate
        )

        var roots = CertificateStore([alternativeRoot])
        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        var result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        switch (match, result) {
        case (true, .validCertificate), (false, .couldNotValidate):

            ()

        default:
            Issue.record(
                "Incorrect validation on excluded subtrees \(permittedSubtrees) for \(subjectAlternativeNames) from root, expected \(match) got \(result)"
            )
        }

        roots = CertificateStore([TestPKI.unconstrainedCA])
        verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([alternativeIntermediate])
        )

        switch (match, result) {
        case (true, .validCertificate), (false, .couldNotValidate):

            ()

        default:
            Issue.record(
                "Incorrect validation on excluded subtrees \(permittedSubtrees) for \(subjectAlternativeNames) from intermediate, expected \(match) got \(result)"
            )
        }

        roots = CertificateStore([alternativeRoot])
        verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        result = await verifier.validate(
            leaf: leafWithoutNames,
            intermediates: CertificateStore([intermediateWithAConstrainedNameForSomeReason])
        )

        switch (match, result) {
        case (true, .validCertificate), (false, .couldNotValidate):

            ()

        default:
            Issue.record(
                "Incorrect validation on excluded subtrees \(permittedSubtrees) for \(subjectAlternativeNames) from intermediate, expected \(match) got \(result)"
            )
        }
    }

    static func _expiredLeafIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 1.0,
            notValidAfter: TestPKI.startDate + 2.0,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 3.0)
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate(let policyFailures) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(policyFailures.count == 1)
    }

    static func _expiredIntermediateIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,

            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter + 2.0,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.unconstrainedIntermediate.notValidAfter + 1.0)
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate(let policyFailures) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(policyFailures.count == 1)
    }

    static func _expiredRootIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,
            notValidAfter: TestPKI.unconstrainedCA.notValidAfter + 2.0,

            issuer: .unconstrainedRoot
        )

        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.unconstrainedCA.notValidAfter + 1.0)
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate(let policyFailures) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(policyFailures.count == 1)
    }

    static func _notYetValidLeafIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 2.0,
            notValidAfter: TestPKI.startDate + 3.0,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 1.0)
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate(let policyFailures) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(policyFailures.count == 1)
    }

    static func _notYetValidIntermediateIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(

            notValidBefore: TestPKI.unconstrainedIntermediate.notValidBefore - 2.0,
            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.unconstrainedIntermediate.notValidBefore - 1.0)
        }

        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate(let policyFailures) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(policyFailures.count == 1)
    }

    static func _notYetValidRootIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.unconstrainedCA.notValidBefore - 2.0,
            notValidAfter: TestPKI.startDate,

            issuer: .unconstrainedRoot
        )

        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.unconstrainedCA.notValidBefore - 1.0)
        }

        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate(let policyFailures) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(policyFailures.count == 1)
    }

    static func _malformedExpiryIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 3.0,
            notValidAfter: TestPKI.startDate + 2.0,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate(let policyFailures) = result else {
            Issue.record("Failed to validate: \(result)")
            return
        }

        #expect(policyFailures.count == 1)
    }

    static func _selfSignedCertsMustBeMarkedAsCA(_ policyFactory: PolicyFactory) async throws {
        let certsAndValidity = [
            (
                TestPKI.issueSelfSignedCert(
                    basicConstraints: .isCertificateAuthority(maxPathLength: nil)
                ), true
            ),
            (
                TestPKI.issueSelfSignedCert(
                    basicConstraints: .isCertificateAuthority(maxPathLength: 0)
                ), true
            ),
            (TestPKI.issueSelfSignedCert(basicConstraints: .notCertificateAuthority), false),
            (
                TestPKI.issueSelfSignedCert(
                    customExtensions: try Certificate.Extensions([Self.brokenBasicConstraints])
                ), false
            ),
            (TestPKI.issueSelfSignedCert(version: .v1), true),
        ]

        for (cert, isValid) in certsAndValidity {
            var verifier = Verifier(rootCertificates: CertificateStore([cert])) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            let result = await verifier.validate(leaf: cert, intermediates: CertificateStore([]))

            switch (result, isValid) {
            case (.validCertificate, true),
                (.couldNotValidate, false):
                ()

            case (_, true):
                Issue.record("Failed to validate: \(result) \(cert)")

            case (_, false):
                Issue.record("Incorrectly validated: \(result) \(cert)")
            }
        }
    }

    static func _intermediateCAMustBeMarkedCAInBasicConstraints(
        _ policyFactory: PolicyFactory
    ) async throws {
        let invalidIntermediateCAs = [

            TestPKI.issueIntermediate(
                name: TestPKI.unconstrainedIntermediateName,
                key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),

                extensions: try! Certificate.Extensions {
                    Critical(
                        BasicConstraints.notCertificateAuthority
                    )
                },
                issuer: .unconstrainedRoot
            ),

            TestPKI.issueIntermediate(
                name: TestPKI.unconstrainedIntermediateName,
                key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
                extensions: Certificate.Extensions(),
                issuer: .unconstrainedRoot
            ),

            TestPKI.issueIntermediate(
                name: TestPKI.unconstrainedIntermediateName,
                key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
                extensions: try Certificate.Extensions([Self.brokenBasicConstraints]),
                issuer: .unconstrainedRoot
            ),
        ]

        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        for badIntermediate in invalidIntermediateCAs {
            var verifier = Verifier(rootCertificates: CertificateStore([TestPKI.unconstrainedCA])) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            var result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([badIntermediate])
            )

            guard case .couldNotValidate = result else {
                Issue.record("Incorrectly validated with \(badIntermediate) in chain")
                return
            }

            verifier = Verifier(rootCertificates: CertificateStore([TestPKI.unconstrainedCA])) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([
                    badIntermediate, TestPKI.unconstrainedIntermediate,
                ])
            )

            guard case .validCertificate(let chain) = result else {
                Issue.record("Unable to validate with both bad and good intermediate in chain")
                return
            }

            #expect(
                Array(chain) == [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA]
            )

            let v1Intermediate = TestPKI.issueIntermediate(
                name: TestPKI.unconstrainedIntermediateName,
                version: .v1,
                key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
                extensions: Certificate.Extensions(),
                issuer: .unconstrainedRoot
            )

            verifier = Verifier(rootCertificates: CertificateStore([TestPKI.unconstrainedCA])) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([v1Intermediate])
            )

            guard case .validCertificate(let chain) = result else {
                Issue.record("Unable to validate with v1 intermediate in chain")
                return
            }

            #expect(Array(chain) == [leaf, v1Intermediate, TestPKI.unconstrainedCA])
        }
    }

    static func _rootCAMustBeMarkedCAInBasicConstraints(_ policyFactory: PolicyFactory) async throws
    {
        let invalidRootCAs = [

            TestPKI.issueCA(

                extensions: try! Certificate.Extensions {
                    Critical(
                        BasicConstraints.notCertificateAuthority
                    )
                }
            ),

            TestPKI.issueCA(extensions: Certificate.Extensions()),

            TestPKI.issueCA(extensions: try Certificate.Extensions([Self.brokenBasicConstraints])),
        ]

        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        for badRoot in invalidRootCAs {
            var verifier = Verifier(
                rootCertificates: CertificateStore([badRoot])
            ) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            var result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
            )

            guard case .couldNotValidate = result else {
                Issue.record("Incorrectly validated with \(badRoot) in chain")
                return
            }

            verifier = Verifier(
                rootCertificates: CertificateStore([badRoot, TestPKI.unconstrainedCA])
            ) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
            )

            guard case .validCertificate(let chain) = result else {
                Issue.record("Unable to validate with both bad and good root in chain")
                return
            }

            #expect(
                Array(chain) == [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA]
            )

            let v1Root = TestPKI.issueCA(version: .v1, extensions: .init())

            verifier = Verifier(rootCertificates: CertificateStore([v1Root])) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
            )

            guard case .validCertificate(let chain) = result else {
                Issue.record("Unable to validate with v1 root in chain")
                return
            }

            #expect(Array(chain) == [leaf, TestPKI.unconstrainedIntermediate, v1Root])
        }
    }

    static func _pathLengthConstraintsFromIntermediatesAreApplied(
        _ policyFactory: PolicyFactory
    ) async throws {

        let secondLevelIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.secondLevelIntermediateName,
            key: .init(TestPKI.secondLevelIntermediateKey.publicKey),

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            },
            issuer: .unconstrainedIntermediate
        )

        let leaf = TestPKI.issueLeaf(issuer: .secondLevelIntermediate)

        var verifier = Verifier(rootCertificates: CertificateStore([TestPKI.unconstrainedCA])) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }

        var result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([
                secondLevelIntermediate, TestPKI.unconstrainedIntermediate,
            ])
        )

        guard case .couldNotValidate = result else {
            Issue.record("Incorrectly validated with \(secondLevelIntermediate) in chain")
            return
        }

        let newFirstLevelIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 1)
                )
            },
            issuer: .unconstrainedRoot
        )

        verifier = Verifier(rootCertificates: CertificateStore([TestPKI.unconstrainedCA])) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }

        result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([
                secondLevelIntermediate, newFirstLevelIntermediate,
                TestPKI.unconstrainedIntermediate,
            ])
        )

        guard case .validCertificate(let chain) = result else {
            Issue.record("Unable to validate with both bad and good intermediate in chain")
            return
        }

        #expect(
            Array(chain) == [
                leaf, secondLevelIntermediate, newFirstLevelIntermediate, TestPKI.unconstrainedCA,
            ]
        )
    }

    static func _pathLengthConstraintsOnRootsAreApplied(_ policyFactory: PolicyFactory) async throws
    {

        let alternativeRoot = TestPKI.issueCA(

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            }
        )

        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        var verifier = Verifier(rootCertificates: CertificateStore([alternativeRoot])) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        var result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate = result else {
            Issue.record("Incorrectly validated with \(alternativeRoot) in chain")
            return
        }

        verifier = Verifier(
            rootCertificates: CertificateStore([alternativeRoot, TestPKI.unconstrainedCA])
        ) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .validCertificate(let chain) = result else {
            Issue.record("Unable to validate with both bad and good intermediate in chain")
            return
        }

        #expect(Array(chain) == [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA])
    }

    static func _pathLengthConstraintsDoesOnlyCountNonSelfIssuedCertificates(
        _ policyFactory: PolicyFactory
    ) async throws {

        let alternativeRoot = TestPKI.issueCA(
            extensions: try Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            }
        )

        let intermediate = TestPKI.issueIntermediate(
            name: alternativeRoot.subject,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
            extensions: try .init {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            },
            issuer: .unconstrainedRoot
        )

        let leaf = TestPKI.issueLeaf(
            issuer: .init(
                name: alternativeRoot.subject,
                key: .init(TestPKI.unconstrainedIntermediateKey)
            )
        )

        var verifier = Verifier(rootCertificates: CertificateStore([alternativeRoot])) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        let result = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore([intermediate])
        )

        guard case .validCertificate(let chain) = result else {
            Issue.record("Unable to validate: \(result)")
            return
        }

        #expect(Array(chain) == [leaf, intermediate, alternativeRoot])
    }

    static func allExcludedSubtreesAreEvaluated(_ policyFactory: PolicyFactory) async throws {

        let names: [GeneralName] = [
            .directoryName(

                try! DistinguishedName {
                    CommonName("Excluded")
                }
            ),
            .uniformResourceIdentifier("http://example.com"),
            .dnsName("example.org"),
            .ipAddress(ISO_8824.OctetString(contentBytes: [127, 0, 0, 1])),
        ]
        let excludedSubtrees = [
            names[0],
            .uniformResourceIdentifier("example.com"),
            names[2],
            .ipAddress(ISO_8824.OctetString(contentBytes: [127, 0, 0, 1, 255, 0, 0, 0])),
        ]
        let alternativeRoot = TestPKI.issueCA(

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    NameConstraints(excludedSubtrees: excludedSubtrees)
                )
            }
        )
        let roots = CertificateStore([alternativeRoot])

        for name in names {
            let leaf = TestPKI.issueLeaf(
                issuer: .unconstrainedIntermediate,
                subjectAlternativeNames: [name]
            )

            var verifier = Verifier(rootCertificates: roots) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            let result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
            )

            guard case .couldNotValidate = result else {
                Issue.record("Unexpectedly validated")
                return
            }
        }
    }

    static func subtreesOfUnknownTypeAlwaysFail(_ policyFactory: PolicyFactory) async throws {
        let subtrees: [GeneralName] = try [
            .otherName(
                .init(typeID: [1, 2, 1, 1], value: ISO_8825.`Any`(erasing: ISO_8824.Null()))
            ),
            .rfc822Name("bar.com"),
            .x400Address(
                ISO_8825.`Any`(erasing: ISO_8824.Null(), withIdentifier: GeneralName.x400AddressTag)
            ),
            .ediPartyName(
                ISO_8825.`Any`(
                    erasing: ISO_8824.Null(),
                    withIdentifier: GeneralName.ediPartyNameTag
                )
            ),
            .registeredID([1, 2, 1, 1]),
        ]
        let leaf = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate
        )

        for name in subtrees {

            var alternativeRoot = TestPKI.issueCA(

                extensions: try! Certificate.Extensions {
                    Critical(
                        BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                    )
                    Critical(
                        NameConstraints(excludedSubtrees: [name])
                    )
                }
            )

            var roots = CertificateStore([alternativeRoot])
            var verifier = Verifier(rootCertificates: roots) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            var result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
            )

            guard case .couldNotValidate = result else {
                Issue.record("Unexpectedly validated")
                return
            }

            alternativeRoot = TestPKI.issueCA(

                extensions: try! Certificate.Extensions {
                    Critical(
                        BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                    )
                    Critical(
                        NameConstraints(permittedSubtrees: [name])
                    )
                }
            )
            let constrainedLeaf = TestPKI.issueLeaf(
                issuer: .unconstrainedIntermediate,
                subjectAlternativeNames: [name]
            )

            roots = CertificateStore([alternativeRoot])
            verifier = Verifier(rootCertificates: roots) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            result = await verifier.validate(
                leaf: constrainedLeaf,
                intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
            )

            guard case .couldNotValidate = result else {
                Issue.record("Unexpectedly validated")
                return
            }
        }
    }

    static func brokenExtensionsPreventValidation(_ policyFactory: PolicyFactory) async throws {
        let alternativeRoot = TestPKI.issueCA(

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    Self.brokenNameConstraints
                )
            }
        )
        let goodRootWithConstraint = TestPKI.issueCA(

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    NameConstraints(excludedSubtrees: [
                        .dnsName("example.com")
                    ])
                )
            }
        )
        let bustedSAN = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate,

            customExtensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                Critical(
                    Self.brokenSubjectAlternativeName
                )
            }
        )
        let goodLeaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        var roots = CertificateStore([alternativeRoot])
        var verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        var result = await verifier.validate(
            leaf: goodLeaf,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate = result else {
            Issue.record("Unexpectedly validated")
            return
        }

        roots = CertificateStore([goodRootWithConstraint])
        verifier = Verifier(rootCertificates: roots) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        result = await verifier.validate(
            leaf: bustedSAN,
            intermediates: CertificateStore([TestPKI.unconstrainedIntermediate])
        )

        guard case .couldNotValidate = result else {
            Issue.record("Unexpectedly validated")
            return
        }
    }

    static func excludedSubtreesBeatPermittedSubtrees(_ policyFactory: PolicyFactory) async throws {

        let name = try! DistinguishedName {
            CommonName("Example")
        }

        let names: [GeneralName] = [
            .dnsName("example.com"),
            .ipAddress(ISO_8824.OctetString(contentBytes: [127, 0, 0, 1, 255, 0, 0, 0])),
            .uniformResourceIdentifier("example.com"),
            .directoryName(name),
        ]

        let alternativeIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),

            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )

                NameConstraints(permittedSubtrees: names, excludedSubtrees: names)
            },
            issuer: .unconstrainedRoot
        )

        let roots = CertificateStore([TestPKI.unconstrainedCA])

        for name in names {
            let leaf = TestPKI.issueLeaf(
                issuer: .unconstrainedIntermediate,
                subjectAlternativeNames: [name]
            )

            var verifier = Verifier(rootCertificates: roots) {
                policyFactory.create(TestPKI.startDate + 2.5)
            }
            let result = await verifier.validate(
                leaf: leaf,
                intermediates: CertificateStore([alternativeIntermediate])
            )

            guard case .couldNotValidate = result else {
                Issue.record("Unexpectedly validated")
                return
            }
        }
    }
}
