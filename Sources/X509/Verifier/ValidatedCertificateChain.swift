@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct ValidatedCertificateChain: Sendable, Collection, RandomAccessCollection, Hashable {
    @usableFromInline
    let validatedChain: [Certificate]

    public typealias Index = Int
    public typealias Element = Certificate

    @inlinable
    public var startIndex: Index { self.validatedChain.startIndex }

    @inlinable
    public var endIndex: Index { self.validatedChain.endIndex }

    @inlinable
    public subscript(index: Index) -> Element {
        self.validatedChain[index]
    }

    @inlinable
    public init(uncheckedCertificateChain: [Certificate]) {
        precondition(
            uncheckedCertificateChain.count > 0,
            "A valid certificate chain contains at least one certificate."
        )
        self.validatedChain = uncheckedCertificateChain
    }

    @inlinable
    package init(_ validatedChain: [Certificate]) {
        precondition(
            validatedChain.count > 0,
            "A valid certificate chain contains at least one certificate."
        )
        self.validatedChain = validatedChain
    }

    @inlinable
    public var leaf: Certificate {

        self.validatedChain.first!
    }

    @inlinable
    public var root: Certificate {

        self.validatedChain.last!
    }
}
