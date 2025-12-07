//
//  Test-AutofillMetadata.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  Test-AutofillMetadata.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class AutofillMetadataTests: XCTestCase {

    func testMetadataInitialization() {
        let ts = Date()
        let metadata = AutofillMetadata(domain: "example.com",
                                        displayUsername: "khoa",
                                        lastModified: ts)

        XCTAssertEqual(metadata.domain, "example.com")
        XCTAssertEqual(metadata.displayUsername, "khoa")
        XCTAssertEqual(metadata.lastModified, ts)
    }

    func testMetadataCodableRoundTrip() throws {
        let metadata = AutofillMetadata(
            domain: "apple.com",
            displayUsername: "john",
            lastModified: Date(timeIntervalSince1970: 12345)
        )

        let encoded = try JSONEncoder().encode(metadata)
        let decoded = try JSONDecoder().decode(AutofillMetadata.self, from: encoded)

        XCTAssertEqual(decoded.domain, metadata.domain)
        XCTAssertEqual(decoded.displayUsername, metadata.displayUsername)
        XCTAssertEqual(decoded.lastModified, metadata.lastModified)
    }

    func testMetadataEquatable() {
        let a = AutofillMetadata(domain: "example.com")
        let b = AutofillMetadata(domain: "example.com")
        let c = AutofillMetadata(domain: "different.com")

        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testMetadataAllowsNilFields() throws {
        let metadata = AutofillMetadata()
        XCTAssertNil(metadata.domain)
        XCTAssertNil(metadata.displayUsername)
        XCTAssertNil(metadata.lastModified)

        let encoded = try JSONEncoder().encode(metadata)
        let decoded = try JSONDecoder().decode(AutofillMetadata.self, from: encoded)

        XCTAssertNil(decoded.domain)
        XCTAssertNil(decoded.displayUsername)
        XCTAssertNil(decoded.lastModified)
    }
}
