@preconcurrency import Crypto

@testable import Certificates

extension Certificate.Verify {

    static let crypto = Certificate.Verify {
        signatureAlgorithm,
        publicKey,
        signature,
        signedBytes in
        switch publicKey.backing {
        case .p256(let keyBytes):
            guard case .ecdsa(let sig) = signature.backing,
                let key = try? P256.Signing.PublicKey(x963Representation: keyBytes),
                let raw = sig.paddedRawRepresentation(coordinateByteCount: 32),
                let inner = try? P256.Signing.ECDSASignature(rawRepresentation: raw)
            else {
                return false
            }
            switch signatureAlgorithm {
            case .ecdsaWithSHA256:
                return key.isValidSignature(inner, for: SHA256.hash(data: signedBytes))

            case .ecdsaWithSHA384:
                return key.isValidSignature(inner, for: SHA384.hash(data: signedBytes))

            case .ecdsaWithSHA512:
                return key.isValidSignature(inner, for: SHA512.hash(data: signedBytes))

            default:
                return false
            }

        case .p384(let keyBytes):
            guard case .ecdsa(let sig) = signature.backing,
                let key = try? P384.Signing.PublicKey(x963Representation: keyBytes),
                let raw = sig.paddedRawRepresentation(coordinateByteCount: 48),
                let inner = try? P384.Signing.ECDSASignature(rawRepresentation: raw)
            else {
                return false
            }
            switch signatureAlgorithm {
            case .ecdsaWithSHA256:
                return key.isValidSignature(inner, for: SHA256.hash(data: signedBytes))

            case .ecdsaWithSHA384:
                return key.isValidSignature(inner, for: SHA384.hash(data: signedBytes))

            case .ecdsaWithSHA512:
                return key.isValidSignature(inner, for: SHA512.hash(data: signedBytes))

            default:
                return false
            }

        case .p521(let keyBytes):
            guard case .ecdsa(let sig) = signature.backing,
                let key = try? P521.Signing.PublicKey(x963Representation: keyBytes),
                let raw = sig.paddedRawRepresentation(coordinateByteCount: 66),
                let inner = try? P521.Signing.ECDSASignature(rawRepresentation: raw)
            else {
                return false
            }
            switch signatureAlgorithm {
            case .ecdsaWithSHA256:
                return key.isValidSignature(inner, for: SHA256.hash(data: signedBytes))

            case .ecdsaWithSHA384:
                return key.isValidSignature(inner, for: SHA384.hash(data: signedBytes))

            case .ecdsaWithSHA512:
                return key.isValidSignature(inner, for: SHA512.hash(data: signedBytes))

            default:
                return false
            }

        case .ed25519(let keyBytes):
            guard case .ed25519 = signatureAlgorithm,
                case .ed25519(let sigBytes) = signature.backing,
                let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyBytes)
            else {
                return false
            }
            return key.isValidSignature(sigBytes, for: signedBytes)
        }
    }
}

extension ECDSASignature {

    func paddedRawRepresentation(coordinateByteCount: Int) -> [UInt8]? {
        guard self.r.count <= coordinateByteCount, self.s.count <= coordinateByteCount else {
            return nil
        }

        var raw = [UInt8]()
        raw.reserveCapacity(2 * coordinateByteCount)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - self.r.count))
        raw.append(contentsOf: self.r)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - self.s.count))
        raw.append(contentsOf: self.s)
        return raw
    }
}
