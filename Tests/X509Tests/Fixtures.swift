import Foundation
import Testing

@testable import Certificates

enum Fixture {

    static func der(_ name: String) throws -> [UInt8] {
        let url = try #require(
            Bundle.module.url(forResource: name, withExtension: "der", subdirectory: "Fixtures"),
            "missing frozen fixture: \(name).der"
        )
        return try [UInt8](Data(contentsOf: url))
    }

    static func certificate(_ name: String) throws -> Certificate {
        try Certificate(derEncoded: try der(name))
    }
}
