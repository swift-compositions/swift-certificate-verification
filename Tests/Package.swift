// swift-tools-version: 6.3.3

import PackageDescription

let package = Package(
    name: "testing",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
        .visionOS(.v26),
    ],
    dependencies: [
        .package(path: ".."),
        .package(url: "https://github.com/swift-iso/swift-iso-8824.git", branch: "main"),
        .package(url: "https://github.com/swift-iso/swift-iso-8825.git", branch: "main"),
        .package(
            url: "https://github.com/swift-primitives/swift-time-primitives.git",
            branch: "main"
        ),
        // Test-only owner of the Crypto-backed Certificate.Verify witness. Keeping this
        // edge in the nested package keeps swift-crypto and apple/swift-asn1 outside the
        // root package's production resolution closure.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.3.0"),
    ],
    targets: [
        .testTarget(
            name: "Certificates Tests",
            dependencies: [
                .product(
                    name: "Certificates",
                    package: "swift-certificate-verification"
                ),
                .product(name: "ISO 8824", package: "swift-iso-8824"),
                .product(name: "ISO 8825", package: "swift-iso-8825"),
                .product(name: "Time Primitive", package: "swift-time-primitives"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "X509Tests",
            // These sources still require the deleted issuance/TestPKI surface or excluded
            // crypto backends. swift-foundations/swift-certificate-verification#8 owns their
            // TestPKI-based restoration; this move preserves the exclusions until it lands.
            exclude: [
                "Certificate Tests.swift",
                "Certificate.DER Tests.swift",
                "Certificate.Signature Tests.swift",
                "CertificateStore Tests.swift",
                "RFC5280Policy Tests.swift",
                "Verifier Tests.swift",
            ],
            resources: [.copy("Fixtures")]
        )
    ],
    swiftLanguageModes: [.v6]
)

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    let ecosystem: [SwiftSetting] = [
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
    ]

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem
}
