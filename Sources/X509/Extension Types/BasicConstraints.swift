import ISO_8824
import ISO_8825

public enum BasicConstraints {

    case isCertificateAuthority(maxPathLength: Int?)

    case notCertificateAuthority

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws(Certificate.Error) {
        guard ext.oid == .X509ExtensionID.basicConstraints else {
            throw Certificate.Error.extension(
                .incorrectOID(expected: .X509ExtensionID.basicConstraints, found: ext.oid)
            )
        }

        let basicConstraintsValue: BasicConstraintsValue
        do {
            basicConstraintsValue = try BasicConstraintsValue(derEncoded: ext.value)
        } catch {
            throw Certificate.Error.der(error)
        }
        if basicConstraintsValue.isCA {
            self = .isCertificateAuthority(maxPathLength: basicConstraintsValue.pathLenConstraint)
        } else {
            self = .notCertificateAuthority
        }
    }
}

extension BasicConstraints: Hashable {}

extension BasicConstraints: Sendable {}

extension BasicConstraints: CustomStringConvertible {
    public var description: String {
        switch self {
        case .isCertificateAuthority(maxPathLength: nil):
            return "CA=TRUE"

        case .isCertificateAuthority(maxPathLength: .some(let maxLen)):
            return "CA=TRUE, maxPathLength=\(maxLen)"

        case .notCertificateAuthority:
            return "CA=FALSE"
        }
    }
}

extension BasicConstraints: CustomDebugStringConvertible {
    public var debugDescription: String {
        "BasicConstraints(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {

    @inlinable
    public init(_ basicConstraints: BasicConstraints, critical: Bool) throws(ISO_8824.Error) {
        let asn1Representation = BasicConstraintsValue(basicConstraints)
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.basicConstraints,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}

@usableFromInline
struct BasicConstraintsValue: ISO_8825.DER.ImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var isCA: Bool

    @usableFromInline
    var pathLenConstraint: Int?

    @inlinable
    init(isCA: Bool, pathLenConstraint: Int?) throws(ISO_8824.Error) {
        self.isCA = isCA
        self.pathLenConstraint = pathLenConstraint

        guard pathLenConstraint == nil || isCA else {
            throw ISO_8824.Error.invalidASN1Object(
                reason:
                    "Invalid combination of isCA (\(isCA)) and path length constraint (\(String(describing: pathLenConstraint))"
            )
        }
    }

    @inlinable
    init(_ ext: BasicConstraints) {
        switch ext {
        case .isCertificateAuthority(maxPathLength: let maxPathLen):
            self.isCA = true
            self.pathLenConstraint = maxPathLen

        case .notCertificateAuthority:
            self.isCA = false
            self.pathLenConstraint = nil
        }
    }

    @inlinable
    init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) {
            (
                nodes: inout ISO_8825.Node.Collection.Iterator
            ) throws(ISO_8824.Error) -> BasicConstraintsValue in
            let isCA: Bool = try ISO_8825.DER.decodeDefault(&nodes, defaultValue: false)
            let pathLenConstraint: Int? = try ISO_8825.DER.optionalImplicitlyTagged(&nodes)
            return try BasicConstraintsValue(isCA: isCA, pathLenConstraint: pathLenConstraint)
        }
    }

    @inlinable
    func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            if isCA != false {
                try coder.serialize(isCA)
            }
            try coder.serializeOptionalImplicitlyTagged(pathLenConstraint)
        }
    }
}
