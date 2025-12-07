//
//  Test-EntryFieldTypes.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  EntryFieldTypesTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class EntryFieldTypesTests: XCTestCase {

    func testAllCasesStable() {
        XCTAssertEqual(
            EntryFieldType.allCases,
            [.username, .password, .notes, .otpSecret, .metadata]
        )
    }

    func testRawValues() {
        XCTAssertEqual(EntryFieldType.username.rawValue, "username")
        XCTAssertEqual(EntryFieldType.password.rawValue, "password")
        XCTAssertEqual(EntryFieldType.notes.rawValue, "notes")
        XCTAssertEqual(EntryFieldType.otpSecret.rawValue, "otpSecret")
        XCTAssertEqual(EntryFieldType.metadata.rawValue, "metadata")
    }

    func testCodableRoundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        for field in EntryFieldType.allCases {
            let data = try encoder.encode(field)
            let decoded = try decoder.decode(EntryFieldType.self, from: data)
            XCTAssertEqual(decoded, field)
        }
    }
}
