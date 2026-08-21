import ISO_8824
import ISO_8825
import Testing

@testable import Certificates

extension GeneralName {
    @Suite struct Test {
        @Suite struct Unit {}
    }
}

extension GeneralName.Test.Unit {

    @Test func `ANY-carrying cases render bare DER bytes`() throws {
        let null = try ISO_8825.`Any`(erasing: ISO_8824.Null())

        #expect(String(describing: GeneralName.ediPartyName(null)) == "EDIPartyName([5, 0])")
        #expect(String(describing: GeneralName.x400Address(null)) == "X400Address([5, 0])")
    }

    @Test func `the other CHOICE cases are unchanged`() throws {
        #expect(
            String(describing: GeneralName.dnsName("www.apple.com"))
                == "DNSName(\"www.apple.com\")"
        )
        #expect(
            String(describing: GeneralName.rfc822Name("mail@example.com"))
                == "RFC822Name(\"mail@example.com\")"
        )
        #expect(
            String(describing: GeneralName.uniformResourceIdentifier("http://www.apple.com/"))
                == "URI(\"http://www.apple.com/\")"
        )
        #expect(
            String(describing: GeneralName.registeredID([1, 2, 3, 4, 5]))
                == "RegisteredID(1.2.3.4.5)"
        )
        let loopback = ISO_8824.OctetString(contentBytes: [127, 0, 0, 1])
        #expect(
            String(describing: GeneralName.ipAddress(loopback))
                == "IPAddress([127, 0, 0, 1])"
        )
    }
}
