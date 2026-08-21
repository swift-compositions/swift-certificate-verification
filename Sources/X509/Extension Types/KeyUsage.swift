import ISO_8824
import ISO_8825

public struct KeyUsage {

    @usableFromInline
    internal var rawValue: UInt16

    @inlinable
    public init() {
        self.rawValue = 0
    }

    @inlinable
    public init(
        digitalSignature: Bool = false,
        nonRepudiation: Bool = false,
        keyEncipherment: Bool = false,
        dataEncipherment: Bool = false,
        keyAgreement: Bool = false,
        keyCertSign: Bool = false,
        cRLSign: Bool = false,
        encipherOnly: Bool = false,
        decipherOnly: Bool = false
    ) {
        self = Self()
        self.digitalSignature = digitalSignature
        self.nonRepudiation = nonRepudiation
        self.keyEncipherment = keyEncipherment
        self.dataEncipherment = dataEncipherment
        self.keyAgreement = keyAgreement
        self.keyCertSign = keyCertSign
        self.cRLSign = cRLSign
        self.encipherOnly = encipherOnly
        self.decipherOnly = decipherOnly
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws(Certificate.Error) {
        guard ext.oid == .X509ExtensionID.keyUsage else {
            throw Certificate.Error.extension(
                .incorrectOID(expected: .X509ExtensionID.keyUsage, found: ext.oid)
            )
        }

        let keyUsageValue: ISO_8824.BitString
        do {
            keyUsageValue = try ISO_8824.BitString(derEncoded: ext.value)
        } catch {
            throw Certificate.Error.der(error)
        }
        do {
            try Self.validateBitString(keyUsageValue)
        } catch {
            throw Certificate.Error.der(error)
        }
        self.rawValue = UInt16(keyUsageValue)
    }

    @inlinable
    public var digitalSignature: Bool {
        get {
            return (self.rawValue & 0x8000) == 0x8000
        }
        set {
            if newValue {
                self.rawValue |= 0x8000
            } else {
                self.rawValue &= (~0x8000)
            }
        }
    }

    @inlinable
    public var nonRepudiation: Bool {
        get {
            return (self.rawValue & 0x4000) == 0x4000
        }
        set {
            if newValue {
                self.rawValue |= 0x4000
            } else {
                self.rawValue &= (~0x4000)
            }
        }
    }

    @inlinable
    public var keyEncipherment: Bool {
        get {
            return (self.rawValue & 0x2000) == 0x2000
        }
        set {
            if newValue {
                self.rawValue |= 0x2000
            } else {
                self.rawValue &= (~0x2000)
            }
        }
    }

    @inlinable
    public var dataEncipherment: Bool {
        get {
            return (self.rawValue & 0x1000) == 0x1000
        }
        set {
            if newValue {
                self.rawValue |= 0x1000
            } else {
                self.rawValue &= (~0x1000)
            }
        }
    }

    @inlinable
    public var keyAgreement: Bool {
        get {
            return (self.rawValue & 0x0800) == 0x0800
        }
        set {
            if newValue {
                self.rawValue |= 0x0800
            } else {
                self.rawValue &= (~0x0800)
            }
        }
    }

    @inlinable
    public var keyCertSign: Bool {
        get {
            return (self.rawValue & 0x0400) == 0x0400
        }
        set {
            if newValue {
                self.rawValue |= 0x0400
            } else {
                self.rawValue &= (~0x0400)
            }
        }
    }

    @inlinable
    public var cRLSign: Bool {
        get {
            return (self.rawValue & 0x0200) == 0x0200
        }
        set {
            if newValue {
                self.rawValue |= 0x0200
            } else {
                self.rawValue &= (~0x0200)
            }
        }
    }

    @inlinable
    public var encipherOnly: Bool {
        get {
            return (self.rawValue & 0x0100) == 0x0100
        }
        set {
            if newValue {
                self.rawValue |= 0x0100
            } else {
                self.rawValue &= (~0x0100)
            }
        }
    }

    @inlinable
    public var decipherOnly: Bool {
        get {
            return (self.rawValue & 0x0080) == 0x0080
        }
        set {
            if newValue {
                self.rawValue |= 0x0080
            } else {
                self.rawValue &= (~0x0080)
            }
        }
    }

    @inlinable
    package static func validateBitString(_ bitstring: ISO_8824.BitString) throws(ISO_8824.Error) {
        switch bitstring.bytes.count {
        case 0:

            precondition(bitstring.paddingBits == 0)

        case 1:

            precondition(bitstring.paddingBits < 8)
            let bitMask = UInt8(0x01) << bitstring.paddingBits
            if (bitstring.bytes[bitstring.bytes.startIndex] & bitMask) == 0 {
                throw ISO_8824.Error.invalidASN1Object(reason: "Invalid leading padding bit")
            }

        case 2 where bitstring.paddingBits == 7:

            if (bitstring.bytes[bitstring.bytes.startIndex &+ 1] & 0x80) == 0 {
                throw ISO_8824.Error.invalidASN1Object(reason: "Invalid padding bit")
            }

        default:

            throw ISO_8824.Error.invalidASN1Object(reason: "Too many bits for Key Usage")
        }
    }
}

extension KeyUsage: Hashable {}

extension KeyUsage: Sendable {}

extension KeyUsage: CustomStringConvertible {
    public var description: String {
        var enabledUsages: [String] = []

        if self.digitalSignature {
            enabledUsages.append("digitalSignature")
        }
        if self.nonRepudiation {
            enabledUsages.append("nonRepudiation")
        }
        if self.keyEncipherment {
            enabledUsages.append("keyEncipherment")
        }
        if self.dataEncipherment {
            enabledUsages.append("dataEncipherment")
        }
        if self.keyAgreement {
            enabledUsages.append("keyAgreement")
        }
        if self.keyCertSign {
            enabledUsages.append("keyCertSign")
        }
        if self.cRLSign {
            enabledUsages.append("cRLSign")
        }
        if self.encipherOnly {
            enabledUsages.append("encipherOnly")
        }
        if self.decipherOnly {
            enabledUsages.append("decipherOnly")
        }

        return enabledUsages.joined(separator: ", ")
    }
}

extension KeyUsage: CustomDebugStringConvertible {
    public var debugDescription: String {
        "KeyUsage(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {

    @inlinable
    public init(_ keyUsage: KeyUsage, critical: Bool) throws(ISO_8824.Error) {
        let asn1Representation = try ISO_8824.BitString(keyUsage)
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.keyUsage,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}

extension UInt16 {
    @inlinable
    package init(_ bitString: ISO_8824.BitString) {
        switch bitString.bytes.count {
        case 0:
            self = 0

        case 1:
            self = UInt16(bitString.bytes[bitString.bytes.startIndex]) << 8

        case 2:
            self = UInt16(bitString.bytes[bitString.bytes.startIndex]) << 8
            self |= UInt16(bitString.bytes[bitString.bytes.startIndex + 1])

        default:
            preconditionFailure()
        }
    }
}

extension ISO_8824.BitString {
    @inlinable
    package init(_ ext: KeyUsage) throws(ISO_8824.Error) {
        if ext.decipherOnly {

            let bytes = [
                UInt8(truncatingIfNeeded: ext.rawValue >> 8),
                UInt8(truncatingIfNeeded: ext.rawValue),
            ]
            self = try .init(bytes: bytes[...], paddingBits: 7)
        } else {

            let byte = UInt8(truncatingIfNeeded: ext.rawValue >> 8)
            self = try .init(bytes: [byte], paddingBits: byte.trailingZeroBitCount)
        }
    }
}
