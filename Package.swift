// swift-tools-version: 6.3.3
// Institute swift-certificates — L3 X.509 chain/verification runtime.
// True fork of apple/swift-certificates at 24ccdeeeed4dfaae7955fcac9dbf5489ed4f1a25
// (1.18.0) per certificates-n5-decision-packet.md GATE B; see NOTICE.txt.
import PackageDescription

let package = Package(
    // Must match the repository/directory name: SwiftPM derives a workspace override's
    // identity from the directory, and rejects the override when the declared name
    // disagrees. Declaring "swift-certificates" here made this package unoverridable.
    name: "swift-certificate-verification",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
        .visionOS(.v26),
    ],
    products: [
        .library(
            name: "Certificates",
            targets: ["Certificates"]
        )
    ],
    dependencies: [
        // Canonical URL deps (final-state posture; global mirrors redirect to local checkouts).
        .package(url: "https://github.com/swift-iso/swift-iso-8824.git", branch: "main"),
        .package(url: "https://github.com/swift-iso/swift-iso-8825.git", branch: "main"),
        .package(url: "https://github.com/swift-primitives/swift-byte-primitives.git", branch: "main"),
        // Direct edge for the typed-throws Optional.map that @inlinable model code now
        // binds (the module is already in the closure via the RFC 791 umbrella; @inlinable
        // requires the direct import).
        .package(url: "https://github.com/swift-primitives/swift-standard-library-extensions.git", branch: "main"),
        // (Q4 time-surface ruling: Instant, lead-approved 2026-07-23)
        .package(url: "https://github.com/swift-primitives/swift-time-primitives.git", branch: "main"),
        // IP presentation/binary parsing (bucket-5 reuse per [IMPL-060]): the RFC owners'
        // text + binary Address parsers replace inet_pton/in_addr/in6_addr/memcmp.
        .package(url: "https://github.com/swift-ietf/swift-rfc-791.git", branch: "main"),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4291.git", branch: "main"),
        // URI presentation parsing (bucket-5 reuse): RFC_3986.URI replaces Foundation.URL
        // for name-constraint host extraction.
        .package(url: "https://github.com/swift-ietf/swift-rfc-3986.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "Certificates",
            dependencies: [
                "Certificate Internals",
                .product(name: "ISO 8824", package: "swift-iso-8824"),
                .product(name: "ISO 8825", package: "swift-iso-8825"),
                .product(name: "Byte Primitives", package: "swift-byte-primitives"),
                .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions"),
                .product(name: "Time Primitive", package: "swift-time-primitives"),
                .product(name: "RFC 791", package: "swift-rfc-791"),
                .product(name: "RFC 4291", package: "swift-rfc-4291"),
                .product(name: "RFC 3986", package: "swift-rfc-3986"),
            ],
            path: "Sources/X509"
        ),
        .target(
            name: "Certificate Internals",
            path: "Sources/_CertificateInternals"
        ),
        .testTarget(
            name: "Certificate Internals Tests",
            dependencies: ["Certificate Internals"],
            path: "Tests/CertificateInternalsTests"
        ),
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
