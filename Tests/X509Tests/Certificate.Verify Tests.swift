@preconcurrency import Crypto
import ISO_8825
import Testing

@testable import Certificates

extension Certificate.Verify {
    @Suite struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
        @Suite struct Integration {}
    }
}

extension Certificate.Verify.Test.Unit {
    @Test func `accepts a genuine self-signed signature`() throws {

        let root = try Fixture.certificate("root-ca")
        #expect(
            Certificate.Verify.crypto.signature(
                root.signatureAlgorithm,
                root.publicKey,
                root.signature,
                root.tbsCertificateBytes
            )
        )
    }

    @Test func `accepts an intermediate signed by its issuer`() throws {

        let root = try Fixture.certificate("root-ca")
        let intermediate = try Fixture.certificate("intermediate-ca")
        #expect(
            Certificate.Verify.crypto.signature(
                intermediate.signatureAlgorithm,
                root.publicKey,
                intermediate.signature,
                intermediate.tbsCertificateBytes
            )
        )
    }

    @Test func `accepts an ed25519 signature`() throws {

        let edRoot = try Fixture.certificate("ed25519-root-ca")
        #expect(
            Certificate.Verify.crypto.signature(
                edRoot.signatureAlgorithm,
                edRoot.publicKey,
                edRoot.signature,
                edRoot.tbsCertificateBytes
            )
        )
    }

    @Test func `stripping and re-padding an ECDSA signature is the identity`() throws {

        let width = 32

        func roundTrips(_ raw: [UInt8]) -> Bool {
            let signature = ECDSASignature(rawSignatureBytes: raw)
            return signature.paddedRawRepresentation(coordinateByteCount: width) == raw
        }

        #expect(roundTrips(Array(repeating: 0x7F, count: 2 * width)))

        #expect(roundTrips(Array(repeating: 0xFF, count: 2 * width)))

        var rLeadingZero = Array(repeating: UInt8(0x11), count: 2 * width)
        rLeadingZero[0] = 0x00
        var sLeadingZero = Array(repeating: UInt8(0x11), count: 2 * width)
        sLeadingZero[width] = 0x00
        var bothLeadingZero = Array(repeating: UInt8(0x11), count: 2 * width)
        bothLeadingZero[0] = 0x00
        bothLeadingZero[width] = 0x00
        #expect(roundTrips(rLeadingZero))
        #expect(roundTrips(sLeadingZero))
        #expect(roundTrips(bothLeadingZero))

        #expect(roundTrips(Array(repeating: 0x00, count: 2 * width)))

        var small = Array(repeating: UInt8(0x00), count: 2 * width)
        small[width - 1] = 0x09
        small[2 * width - 1] = 0x07
        #expect(roundTrips(small))
    }

    @Test func `the parked Crypto initialisers agree with the DER parse path`() throws {
        func agrees(_ modelled: Certificate.PublicKey) throws -> Bool {
            var serializer = ISO_8825.DER.Serializer()
            try serializer.serialize(SubjectPublicKeyInfo(modelled))
            let spki = try SubjectPublicKeyInfo(derEncoded: serializer.serializedBytes)
            return try Certificate.PublicKey(spki: spki) == modelled
        }

        #expect(try agrees(Certificate.PublicKey(P256.Signing.PrivateKey().publicKey)))
        #expect(try agrees(Certificate.PublicKey(P384.Signing.PrivateKey().publicKey)))
        #expect(try agrees(Certificate.PublicKey(P521.Signing.PrivateKey().publicKey)))
        #expect(try agrees(Certificate.PublicKey(Curve25519.Signing.PrivateKey().publicKey)))
    }
}

extension Certificate.Verify.Test.`Edge Case` {
    @Test func `rejects a certificate whose TBS bytes were tampered with`() throws {

        let intermediate = try Fixture.certificate("intermediate-ca")
        let tampered = try Fixture.certificate("leaf-tampered-tbs")
        #expect(
            !Certificate.Verify.crypto.signature(
                tampered.signatureAlgorithm,
                intermediate.publicKey,
                tampered.signature,
                tampered.tbsCertificateBytes
            )
        )
    }

    @Test func `rejects a signature made by an unrelated key`() throws {

        let intermediate = try Fixture.certificate("intermediate-ca")
        let wrongKey = try Fixture.certificate("leaf-wrong-key-signature")
        #expect(
            !Certificate.Verify.crypto.signature(
                wrongKey.signatureAlgorithm,
                intermediate.publicKey,
                wrongKey.signature,
                wrongKey.tbsCertificateBytes
            )
        )
    }

    @Test func `rejects a genuine signature checked against the wrong key`() throws {

        let root = try Fixture.certificate("root-ca")
        let intermediate = try Fixture.certificate("intermediate-ca")
        #expect(
            !Certificate.Verify.crypto.signature(
                intermediate.signatureAlgorithm,
                intermediate.publicKey,
                intermediate.signature,
                intermediate.tbsCertificateBytes
            )
        )

        #expect(
            Certificate.Verify.crypto.signature(
                intermediate.signatureAlgorithm,
                root.publicKey,
                intermediate.signature,
                intermediate.tbsCertificateBytes
            )
        )
    }

    @Test func `the rejecting witness rejects a genuine signature`() throws {

        let root = try Fixture.certificate("root-ca")
        #expect(
            !Certificate.Verify.rejectingAll.signature(
                root.signatureAlgorithm,
                root.publicKey,
                root.signature,
                root.tbsCertificateBytes
            )
        )
    }
}
