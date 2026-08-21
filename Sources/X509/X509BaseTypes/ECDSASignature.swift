import ISO_8824
import ISO_8825

@usableFromInline
struct ECDSASignature: ISO_8825.DER.ImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var r: ArraySlice<UInt8>

    @usableFromInline
    var s: ArraySlice<UInt8>

    @inlinable
    init(r: ArraySlice<UInt8>, s: ArraySlice<UInt8>) {
        self.r = r
        self.s = s
    }

    @inlinable
    init(
        derEncoded rootNode: ISO_8825.Node,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) {
            (
                nodes: inout ISO_8825.Node.Collection.Iterator
            ) throws(ISO_8824.Error) -> ECDSASignature in
            let r = try ArraySlice<UInt8>(derEncoded: &nodes)
            let s = try ArraySlice<UInt8>(derEncoded: &nodes)

            return ECDSASignature(r: r, s: s)
        }
    }

    @inlinable
    func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) {
            (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(r)
            try coder.serialize(s)
        }
    }

    @inlinable
    init(rawSignatureBytes raw: [UInt8]) {
        let half = raw.count / 2
        let r = ArraySlice(normalisingToASN1IntegerForm: raw.prefix(upTo: half))
        let s = ArraySlice(normalisingToASN1IntegerForm: raw.suffix(from: half))

        self = ECDSASignature(r: r, s: s)
    }
}

extension ArraySlice where Element == UInt8 {

    @inlinable
    package init<Bytes: Collection>(normalisingToASN1IntegerForm bigEndianRawInteger: Bytes)
    where Bytes.Element == UInt8 {
        let realBytes = bigEndianRawInteger.drop(while: { $0 == 0 })
        self = ArraySlice(realBytes)
    }

    @inlinable
    package init(normalisingToASN1IntegerForm bigEndianRawInteger: ArraySlice<UInt8>) {
        self = bigEndianRawInteger.drop(while: { $0 == 0 })
    }

    @inlinable
    package init(normalisingToASN1IntegerForm bigEndianRawInteger: [UInt8]) {
        self.init(normalisingToASN1IntegerForm: bigEndianRawInteger[...])
    }
}
