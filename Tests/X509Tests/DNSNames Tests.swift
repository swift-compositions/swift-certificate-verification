import ISO_8824
import ISO_8825
import Testing

@testable import Certificates

@Suite struct `DNSNames Tests` {

    static let fixtures: [(String, String, Bool)] = [
        ("", "a", false),
        ("a", "a", true),
        ("b", "a", false),
        ("*.b.a", "c.b.a", false),
        ("*.b.a", "b.a", true),
        ("*.b.a", "b.a.", true),

        ("d.c.b.a", "d.c.b.a", true),
        ("d.*.b.a", "d.c.b.a", false),
        ("d.c*.b.a", "d.c.b.a", false),
        ("d.c*.b.a", "d.cc.b.a", false),

        (
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            true
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz",
            true
        ),
        ("aBc", "Abc", true),

        ("a1", "a1", true),

        ("example", "example", true),
        ("example.", "example.", false),
        ("example", "example.", true),
        ("example.", "example", false),
        ("example.com", "example.com", true),
        ("example.com.", "example.com.", false),
        ("example.com", "example.com.", true),
        ("example.com.", "example.com", false),
        ("example.com..", "example.com.", false),
        ("example.com..", "example.com", false),
        ("example.com...", "example.com.", false),

        ("x*.b.a", "xa.b.a", false),
        ("x*.b.a", "xna.b.a", false),
        ("x*.b.a", "xn-a.b.a", false),
        ("x*.b.a", "xn--a.b.a", false),
        ("xn*.b.a", "xn--a.b.a", false),
        ("xn-*.b.a", "xn--a.b.a", false),
        ("xn--*.b.a", "xn--a.b.a", false),
        ("xn*.b.a", "xn--a.b.a", false),
        ("xn-*.b.a", "xn--a.b.a", false),
        ("xn--*.b.a", "xn--a.b.a", false),
        ("xn---*.b.a", "xn--a.b.a", false),

        ("c*.b.a", "c.b.a", false),

        ("foo.com", "foo.com", true),
        ("f", "f", true),
        ("i", "h", false),
        ("*.foo.com", "bar.foo.com", false),
        ("*.test.fr", "www.test.fr", false),
        ("*.test.FR", "wwW.tESt.fr", false),
        (".uk", "f.uk", false),
        ("?.bar.foo.com", "w.bar.foo.com", false),
        ("(www|ftp).foo.com", "www.foo.com", false),
        ("www.foo.com\0", "www.foo.com", false),
        ("www.foo.com\0*.foo.com", "www.foo.com", false),
        ("ww.house.example", "www.house.example", false),
        ("www.test.org", "test.org", true),
        ("*.test.org", "test.org", true),
        ("*.org", "test.org", false),

        ("w*.bar.foo.com", ".bar.foo.com", false),
        ("ww*ww.bar.foo.com", ".bar.foo.com", false),
        ("ww*ww.bar.foo.com", ".bar.foo.com", false),
        ("w*w.bar.foo.com", ".bar.foo.com", false),
        ("w*w.bar.foo.c0m", ".bar.foo.com", false),
        ("wa*.bar.foo.com", ".bar.foo.com", false),
        ("*Ly.bar.foo.com", ".bar.foo.com", false),
        ("*.test.de", "www.test.co.jp", false),
        ("*.jp", "www.test.co.jp", false),
        ("www.test.co.uk", "www.test.co.jp", false),
        ("www.*.co.jp", "www.test.co.jp", false),
        ("www.bar.foo.com", "www.bar.foo.com", true),
        ("*.foo.com", "www.bar.foo.com", false),
        ("*.*.foo.com", "www.bar.foo.com", false),
        ("www.bath.org", "www.bath.org", true),

        (
            "xn--poema-9qae5a.com.br",
            "xn--poema-9qae5a.com.br",
            true
        ),
        (
            "*.xn--poema-9qae5a.com.br",
            "www.xn--poema-9qae5a.com.br",
            false
        ),
        (
            "*.xn--poema-9qae5a.com.br",
            "xn--poema-9qae5a.com.br",
            true
        ),
        ("xn--poema-*.com.br", "xn--poema-9qae5a.com.br", false),
        ("xn--*-9qae5a.com.br", "xn--poema-9qae5a.com.br", false),
        ("*--poema-9qae5a.com.br", "xn--poema-9qae5a.com.br", false),

        ("*.example.com", "foo.example.com", false),
        ("*.example.com", "bar.foo.example.com", false),
        ("*.example.com", "example.com", true),
        ("baz*.example.net", "baz1.example.net", false),
        ("*baz.example.net", "foobaz.example.net", false),
        ("b*z.example.net", "buzz.example.net", false),

        ("*.test.example", ".test.example", true),
        ("*.example.co.uk", ".example.co.uk", true),
        ("*.example", ".example", false),

        ("*.co.uk", ".co.uk", true),
        ("*.com", ".com", false),
        ("*.us", ".us", false),
        ("*", "foo", false),

        (
            "*.xn--poema-9qae5a.com.br",
            ".xn--poema-9qae5a.com.br",
            true
        ),
        (
            "*.example.xn--mgbaam7a8h",
            ".example.xn--mgbaam7a8h",
            true
        ),
        ("*.xn--mgbaam7a8h", ".xn--mgbaam7a8h", false),

        ("*.appspot.com", ".appspot.com", true),
        ("*.s3.amazonaws.com", ".s3.amazonaws.com", true),

        ("*.*.com", ".com", false),
        ("*.bar.*.com", ".com", false),

        ("foo.com.", "foo.com", false),
        ("foo.com", "foo.com.", true),
        ("foo.com.", "foo.com.", false),
        ("f.", "f", false),
        ("f", "f.", true),
        ("f.", "f.", false),
        ("*.bar.foo.com.", ".bar.foo.com", false),
        ("*.bar.foo.com", ".bar.foo.com.", true),
        ("*.bar.foo.com.", ".bar.foo.com.", false),
        ("*.com.", "example.com", false),
        ("*.com", "example.com.", false),
        ("*.com.", "example.com.", false),
        ("*.", "foo.", false),
        ("*.", "foo", false),

        ("*.co.uk.", "foo.co.uk", false),
        ("*.co.uk.", "foo.co.uk.", false),

        ("example.com", "", true),
        ("*.foo.example.com", "", true),

        ("example.com", "foo.example.com", false),

        (
            Array(repeating: "example", count: 31).joined(separator: ".") + ".com.au",
            ".example.com.au", false
        ),
        (
            "example.com.au",
            Array(repeating: "example", count: 31).joined(separator: ".") + ".com.au", false
        ),

        ("-.example.com", "example.com", false),
        ("foo.-bar.example.com", "example.com", false),
        ("foo-.example.com", "example.com", false),
        ("foo-bar.example.com", "example.com", true),
        ("foo.-example.com", "-example.com", false),
        ("foo.-bar.example.com", "foo.-bar.example.com", false),
        ("foo.bar-.example.com", "foo.bar-.example.com", false),
        ("foo-bar.example.com", "foo-bar.example.com", true),

        ("\(String(repeating: "a", count: 63)).example.com", "example.com", true),
        ("\(String(repeating: "a", count: 64)).example.com", "example.com", false),
        (
            "\(String(repeating: "a", count: 63)).example.com",
            "\(String(repeating: "a", count: 63)).example.com", true
        ),
        (
            "\(String(repeating: "a", count: 64)).example.com",
            "\(String(repeating: "a", count: 64)).example.com", false
        ),

        ("1234567.example.com", "example.com", true),
        ("foo.1234567.example.com", "foo.1234567.example.com", true),
        ("foo.example.123", "foo.example.123", false),

        ("foo.com", "example.bar.", false),
        ("foo.com", "foo.www.", false),
    ]

    static func urisThatMatch(_ dnsName: String) -> [String] {
        return [
            "http://\(dnsName)/",
            "https://\(dnsName)",
            "http://user:password@\(dnsName)",
            "http://\(dnsName)/index.html",
            "https://\(dnsName)/foo/bar/baz?x=y",
            "ftp://user:password@\(dnsName):4343/cat.txt",
        ]
    }

    static func urisThatDontMatch(_ dnsName: String) -> [String] {
        return [

            "http://\(dnsName):\(dnsName)@sir.not.appearing.in.this.movie",

            "\(dnsName)://sir.not.appearing.in.this.movie/",

            "http://sir.not.appearing.in.this.movie/\(dnsName)/baz",

            "http://127.0.0.1",
            "http://[fe80::1]",

            "/foo/bar",
            "\(dnsName)",
        ]
    }

    @Suite struct Unit {
        @Test func `name matches reference`() throws {
            for (dnsName, constraint, match) in `DNSNames Tests`.fixtures {
                #expect(
                    match
                        == NameConstraintsPolicy.dnsNameMatchesConstraint(
                            dnsName: dnsName.utf8,
                            constraint: constraint.utf8
                        )
                )
            }
        }

        @Test func `reverse DNS labels`() throws {
            func reverse(_ string: String) -> [Substring] {
                return Array(ReverseDNSLabelSequence(string.utf8[...])).map { Substring($0) }
            }

            #expect(reverse("f.") == ["", "f"])
            #expect(reverse("www-3.example.com") == ["com", "example", "www-3"])
            #expect(reverse("f....y.") == ["", "y", "", "", "", "f"])
            #expect(reverse(".example.com") == ["com", "example", ""])
        }
    }

    @Suite struct `Edge Case` {}

    @Suite struct Integration {
        @Test func `URI names match reference hostname`() throws {

            for (dnsName, constraint, match) in `DNSNames Tests`.fixtures {
                for uri in `DNSNames Tests`.urisThatMatch(dnsName) {
                    #expect(
                        match
                            == NameConstraintsPolicy.uriNameMatchesConstraint(
                                uriName: uri,
                                constraint: constraint
                            )
                    )

                    #expect(
                        !NameConstraintsPolicy.uriNameMatchesConstraint(
                            uriName: constraint,
                            constraint: uri
                        )
                    )
                }

                if constraint.isEmpty {

                    continue
                }

                for uri in `DNSNames Tests`.urisThatDontMatch(dnsName) {
                    #expect(
                        !NameConstraintsPolicy.uriNameMatchesConstraint(
                            uriName: uri,
                            constraint: constraint
                        )
                    )
                }
            }
        }
    }
}
