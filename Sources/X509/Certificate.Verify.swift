@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public struct Verify: Sendable {

        public var signature:
            @Sendable (
                _ signatureAlgorithm: Certificate.SignatureAlgorithm,
                _ publicKey: Certificate.PublicKey,
                _ signature: Certificate.Signature,
                _ signedBytes: ArraySlice<UInt8>
            ) -> Bool

        @inlinable
        public init(
            signature:
                @escaping @Sendable (
                    _ signatureAlgorithm: Certificate.SignatureAlgorithm,
                    _ publicKey: Certificate.PublicKey,
                    _ signature: Certificate.Signature,
                    _ signedBytes: ArraySlice<UInt8>
                ) -> Bool
        ) {
            self.signature = signature
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Verify {

    public static let rejectingAll = Certificate.Verify { _, _, _, _ in false }
}
