//
//  VaultEntryMetadataTests.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//


//
//  VaultEntryMetadataTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class VaultEntryMetadataTests: XCTestCase {

    func testEncodeDecodeRoundTrip() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        let meta = VaultEntryMetadata(
            lastCopiedUsername: now,
            lastCopiedPassword: nil,
            lastUsedOTP: now,
            lastViewed: nil
        )

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let data = try encoder.encode(meta)
        let decoded = try decoder.decode(VaultEntryMetadata.self, from: data)

        XCTAssertEqual(decoded.lastCopiedUsername, now)
        XCTAssertNil(decoded.lastCopiedPassword)
        XCTAssertEqual(decoded.lastUsedOTP, now)
        XCTAssertNil(decoded.lastViewed)
    }

    func testDecodeFailsOnCorruptedJSON() {
        let corrupted = Data([0xFF, 0x00, 0xAA])

        let decoder = JSONDecoder()
        XCTAssertThrowsError(
            try decoder.decode(VaultEntryMetadata.self, from: corrupted)
        )
    }
}
