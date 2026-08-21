import ISO_8824

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Error {

    public enum Algorithm: Hashable, Sendable {

        case unsupportedSignature(ISO_8824.ObjectIdentifier)

        case unsupportedPublicKey(ISO_8824.ObjectIdentifier)

        case unsupportedDigest(ISO_8824.ObjectIdentifier)
    }
}
