//
//  Test-AutofillPasswordPayload.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  Test-AutofillPasswordPayload.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class AutofillPasswordPayloadTests: XCTestCase {

    func testPayloadInitialization() {
        let id = UUID()
        let ciphertext = Data([0x01, 0x02, 0x03])
        let nonce = Data([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

        let payload = AutofillPasswordPayload(
            entryID: id,
            encryptedPassword: ciphertext,
            nonce: nonce,
            metadata: AutofillMetadata(domain: "google.com")
        )

        XCTAssertEqual(payload.version, AutofillPasswordPayload.currentVersion)
        XCTAssertEqual(payload.entryID, id)
        XCTAssertEqual(payload.encryptedPassword, ciphertext)
        XCTAssertEqual(payload.nonce, nonce)
        XCTAssertEqual(payload.metadata?.domain, "google.com")
    }

    func testCodableRoundTrip() throws {
        let payload = AutofillPasswordPayload(
            entryID: UUID(),
            encryptedPassword: Data([0x10, 0x20]),
            nonce: Data([0,1,2,3,4,5,6,7,8,9,10,11]),
            metadata: AutofillMetadata(domain: "example.com",
                                       displayUsername: "khoa")
        )

        let encoded = try JSONEncoder().encode(payload)
        let decoded = try JSONDecoder().decode(AutofillPasswordPayload.self, from: encoded)

        XCTAssertEqual(decoded.version, AutofillPasswordPayload.currentVersion)
        XCTAssertEqual(decoded.entryID, payload.entryID)
        XCTAssertEqual(decoded.encryptedPassword, payload.encryptedPassword)
        XCTAssertEqual(decoded.nonce, payload.nonce)
        XCTAssertEqual(decoded.metadata?.domain, "example.com")
        XCTAssertEqual(decoded.metadata?.displayUsername, "khoa")
    }

    func testWithoutMetadata() throws {
        let payload = AutofillPasswordPayload(
            entryID: UUID(),
            encryptedPassword: Data([0x55]),
            nonce: Data([0,1,2,3,4,5,6,7,8,9,10,11]),
            metadata: nil
        )

        XCTAssertNil(payload.metadata)

        let encoded = try JSONEncoder().encode(payload)
        let decoded = try JSONDecoder().decode(AutofillPasswordPayload.self, from: encoded)

        XCTAssertNil(decoded.metadata)
    }
}
