import ISO_8824

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public enum Error: Swift.Error, Hashable, Sendable {

        case algorithm(Algorithm)

        case signature(Signature)

        case `extension`(Extension)

        case der(ISO_8824.Error)
    }
}
