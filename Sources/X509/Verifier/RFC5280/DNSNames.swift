@usableFromInline
let asciiPeriod = UInt8(ascii: "." as Unicode.Scalar)

@usableFromInline
let asciiAsterisk = UInt8(ascii: "*" as Unicode.Scalar)

@usableFromInline
let asciiHyphen = UInt8(ascii: "-" as Unicode.Scalar)

@usableFromInline
let asciiLowercaseA = UInt8(ascii: "a" as Unicode.Scalar)

@usableFromInline
let asciiLowercaseZ = UInt8(ascii: "z" as Unicode.Scalar)

@usableFromInline
let asciiUppercaseA = UInt8(ascii: "A" as Unicode.Scalar)

@usableFromInline
let asciiUppercaseZ = UInt8(ascii: "Z" as Unicode.Scalar)

@usableFromInline
let asciiZero = UInt8(ascii: "0" as Unicode.Scalar)

@usableFromInline
let asciiNine = UInt8(ascii: "9" as Unicode.Scalar)

@usableFromInline
let asciiUnderscore = UInt8(ascii: "_" as Unicode.Scalar)

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraintsPolicy {

    @inlinable
    package static func dnsNameMatchesConstraint(
        dnsName: String.UTF8View,
        constraint: String.UTF8View
    ) -> Bool {

        guard
            dnsName.isValidDNSName(isConstraint: false)
                && constraint.isValidDNSName(isConstraint: true)
        else {
            return false
        }

        if constraint.count == 0 {
            return true
        }

        let dnsName = dnsName[...]
        var constraint = constraint[...]

        if constraint.last == asciiPeriod {
            constraint = constraint.dropLast()
        }

        var reverseDNSNameLabels = ReverseDNSLabelSequence(dnsName).makeIterator()
        var reverseConstraintLabels = ReverseDNSLabelSequence(constraint).makeIterator()

        while true {
            let nextDNSNameLabel = reverseDNSNameLabels.next()
            let nextConstraintLabel = reverseConstraintLabels.next()

            switch (nextDNSNameLabel, nextConstraintLabel) {
            case (.none, .none):

                return true

            case (.some, .none):

                return true

            case (.none, .some):

                return false

            case (.some(let dnsLabel), _) where dnsLabel.count == 0:

                return false

            case (.some, .some(let constraintLabel)) where constraintLabel.count == 0:

                guard reverseConstraintLabels.hasMoreLabels else {

                    return true
                }

                return false

            case (.some(let dnsLabel), .some(let constraintLabel))
            where dnsLabel.caseInsensitiveASCIIMatch(constraintLabel):

                continue

            case (.some, .some):

                return false
            }
        }
    }
}

extension String.UTF8View {

    @usableFromInline
    static let maximumLabelLength = 63

    @inlinable
    package func isValidDNSName(isConstraint: Bool) -> Bool {
        var bytes = self[...]
        var labelCount = 0
        var isWildcard = false

        if bytes.count > 253 {
            return false
        }

        if bytes.first == asciiAsterisk {
            bytes = bytes.dropFirst()
            guard let next = bytes.popFirst(), next == asciiPeriod else {

                return false
            }

            labelCount += 1
            isWildcard = true
        }

        while bytes.count > 0 {
            let label: String.UTF8View.SubSequence
            if let nextPeriod = bytes.firstIndex(of: asciiPeriod) {
                label = bytes[..<nextPeriod]

                let indexAfterPeriod = bytes.index(after: nextPeriod)
                bytes = bytes[indexAfterPeriod...]
            } else {

                label = bytes
                bytes = bytes[bytes.endIndex...]
            }

            labelCount += 1

            if label.count == 0 && !(labelCount == 1 && isConstraint) {
                return false
            }

            if label.first == asciiHyphen || label.last == asciiHyphen {
                return false
            }

            if label.count > Self.maximumLabelLength {
                return false
            }

            switch label.labelContents {
            case .allASCII(let nonNumerics) where nonNumerics > 0:

                continue

            case .allASCII where bytes.count > 0:

                continue

            case .allASCII:

                assert(bytes.count == 0)
                return false

            case .nonASCII:

                return false
            }
        }

        if isWildcard && labelCount < 3 {
            return false
        }

        return true

    }
}

@usableFromInline
struct ReverseDNSLabelSequence: Sequence, Sendable {
    @usableFromInline
    var base: String.UTF8View.SubSequence

    @inlinable
    init(_ base: String.UTF8View.SubSequence) {
        self.base = base
    }

    @inlinable
    func makeIterator() -> Iterator {
        return Iterator(self.base)
    }

    @usableFromInline
    struct Iterator: IteratorProtocol, Sendable {
        @usableFromInline
        var base: String.UTF8View.SubSequence?

        @inlinable
        init(_ base: String.UTF8View.SubSequence) {
            self.base = base
        }

        @inlinable mutating func next() -> String.UTF8View.SubSequence? {

            guard let base = self.base else {
                return nil
            }

            guard let periodIndex = base.lastIndex(of: asciiPeriod) else {

                let label = base
                self.base = nil
                return label
            }

            let labelStartIndex = base.index(after: periodIndex)
            let label = base[labelStartIndex...]
            self.base = base[..<periodIndex]
            return label
        }

        @inlinable var hasMoreLabels: Bool {
            return self.base != nil
        }
    }
}

extension String.UTF8View.SubSequence {
    @usableFromInline
    static let asciiCaseInsensitiveMask: UInt8 = ~(1 << 5)

    @inlinable
    package func caseInsensitiveASCIIMatch(_ other: Self) -> Bool {
        guard self.count == other.count else {
            return false
        }

        return self.elementsEqual(
            other,
            by: { selfByte, otherByte in
                (selfByte & Self.asciiCaseInsensitiveMask)
                    == (otherByte & Self.asciiCaseInsensitiveMask)
            }
        )
    }

    @usableFromInline
    package enum LabelContents: Sendable {
        case allASCII(nonNumerics: Int)
        case nonASCII
    }

    @inlinable
    package var labelContents: LabelContents {
        var nonNumerics = 0

        for byte in self {
            switch byte {
            case asciiZero...asciiNine:
                ()

            case asciiLowercaseA...asciiLowercaseZ,
                asciiUppercaseA...asciiUppercaseZ,
                asciiHyphen, asciiUnderscore:
                nonNumerics += 1

            default:
                return .nonASCII
            }
        }

        return .allASCII(nonNumerics: nonNumerics)
    }
}
