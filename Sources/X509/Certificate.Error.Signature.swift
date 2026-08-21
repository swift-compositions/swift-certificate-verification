@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Error {

    public enum Signature: Hashable, Sendable {

        case invalidForCertificate

        case invalidEncoding(reason: String)
    }
}
