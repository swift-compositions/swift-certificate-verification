@preconcurrency import Crypto

@testable import Certificates

extension Certificate.PublicKey {

    public init(_ p256: P256.Signing.PublicKey) {
        self.init(backing: .p256(x963: Array(p256.x963Representation)))
    }

    public init(_ p384: P384.Signing.PublicKey) {
        self.init(backing: .p384(x963: Array(p384.x963Representation)))
    }

    public init(_ p521: P521.Signing.PublicKey) {
        self.init(backing: .p521(x963: Array(p521.x963Representation)))
    }

    public init(_ ed25519: Curve25519.Signing.PublicKey) {
        self.init(backing: .ed25519(raw: Array(ed25519.rawRepresentation)))
    }
}
