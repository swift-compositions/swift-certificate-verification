import ISO_8824
import ISO_8825

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Error {

    public enum Extension: Hashable, Sendable {

        case incorrectOID(expected: ISO_8824.ObjectIdentifier, found: ISO_8824.ObjectIdentifier)

        case duplicateOID(ISO_8824.ObjectIdentifier)
    }
}
