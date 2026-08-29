// swift-tools-version: 6.4

import PackageDescription

let package = Package(

    name: "swift-certificate-verification",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
    ],
    products: [
        .library(
            name: "Certificates",
            targets: ["Certificates"]
        )
    ],
    dependencies: [

        .package(url: "https://github.com/swift-iso/swift-iso-8824.git", branch: "main"),
        .package(url: "https://github.com/swift-iso/swift-iso-8825.git", branch: "main"),
        .package(
            url: "https://github.com/swift-molecules/swift-byte.git",
            branch: "main"
        ),

        .package(
            url: "https://github.com/swift-atoms/swift-standard-library-extensions.git",
            branch: "main"
        ),

        .package(
            url: "https://github.com/swift-molecules/swift-time.git",
            branch: "main"
        ),

        .package(url: "https://github.com/swift-ietf/swift-rfc-791.git", branch: "main"),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4291.git", branch: "main"),

        .package(url: "https://github.com/swift-ietf/swift-rfc-3986.git", branch: "main"),

        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.3.0"),
    ],
    targets: [
        .target(
            name: "Certificates",
            dependencies: [
                "Certificate Internals",
                .product(name: "ISO 8824", package: "swift-iso-8824"),
                .product(name: "ISO 8825", package: "swift-iso-8825"),
                .product(name: "Byte", package: "swift-byte"),
                .product(
                    name: "Standard Library Extensions",
                    package: "swift-standard-library-extensions"
                ),
                .product(name: "Time Primitive", package: "swift-time"),
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
            name: "Certificates Tests",
            dependencies: [
                "Certificates",
                "Certificate Internals",
                .product(name: "Time Primitive", package: "swift-time"),

                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Tests/X509Tests",

            exclude: [
                "Certificate Tests.swift",
                "Certificate.DER Tests.swift",
                "Certificate.Signature Tests.swift",
                "CertificateStore Tests.swift",
                "RFC5280Policy Tests.swift",
                "Verifier Tests.swift",
            ],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(
            name: "Certificate Internals Tests",
            dependencies: ["Certificate Internals"],
            path: "Tests/CertificateInternalsTests"
        ),
    ]
)
