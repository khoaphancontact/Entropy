//
//  Test-VaultSerialization.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultSerializationTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class VaultSerializationTests: XCTestCase {

    // MARK: - Helpers

    private func makeVaultKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0xAA, count: 32))
    }

    private func makeHeader(now: Date = Date()) -> VaultFileHeader {
        let kdf = VaultKDFParamsSnapshot(
            memoryKiB: 65_536,
            iterations: 2,
            parallelism: 2,
            saltLength: 16
        )
        return VaultFileHeader.newVaultHeader(now: now, kdfParams: kdf)
    }

    // Simple placeholder for inner model JSON
    private func makeInnerPayload() -> Data {
        // In Milestone G this will be JSON of VaultModelV1.
        // For now, it's just deterministic sample JSON.
        let dict: [String: String] = ["model": "v1", "kind": "test"]
        return try! JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
    }

    // MARK: - Encode/Decode Round Trip

    func testEncodeDecodeRoundTrip() throws {
        let key = makeVaultKey()
        let header = makeHeader()
        let payload = makeInnerPayload()

        let fileData = try VaultSerialization.encodeVaultFile(
            header: header,
            plaintext: payload,
            vaultKey: key
        )

        let (decodedHeader, bundle) = try VaultSerialization.decodeVaultFile(fileData)

        XCTAssertEqual(decodedHeader.vaultVersion, VaultFileHeader.currentVaultVersion)
        XCTAssertEqual(decodedHeader.schemaVersion, VaultFileHeader.currentSchemaVersion)
        XCTAssertFalse(bundle.ciphertext.isEmpty)

        // Decrypt and verify inner payload matches
        let decrypted = try VaultEncryption.decryptEntry(
            bundle,
            vaultKey: key
        )
        let decodedPayload = try decrypted.withBytes { Data($0) }
        XCTAssertEqual(decodedPayload, payload)
    }

    // MARK: - Tamper Detection via Hash Mismatch

    func testHashMismatchFails() throws {
        let key = makeVaultKey()
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let header = makeHeader(now: now)
        let payload = makeInnerPayload()

        // Valid file first
        let fileData = try VaultSerialization.encodeVaultFile(
            header: header,
            plaintext: payload,
            vaultKey: key
        )

        // Decode header so we can rebuild a header with a wrong integrity hash
        let decodedHeader = try VaultFileHeader.decode(from: fileData)

        // Create a tampered header with bogus hash but same layout
        let badHash = Data(repeating: 0xFF, count: VaultFileHeader.integrityHashLength)
        let tamperedHeader = VaultFileHeader(
            vaultVersion: decodedHeader.vaultVersion,
            schemaVersion: decodedHeader.schemaVersion,
            createdAt: decodedHeader.createdAt,
            modifiedAt: decodedHeader.modifiedAt,
            encryptionMethod: decodedHeader.encryptionMethod,
            kdfParams: decodedHeader.kdfParams,
            integrityHash: badHash
        )

        let tamperedHeaderData = try tamperedHeader.encodeToData()
        // Ciphertext JSON = original file minus original header
        let originalHeaderData = try decodedHeader.encodeToData()
        let cipherJSON = fileData.dropFirst(originalHeaderData.count)

        let tamperedFile = tamperedHeaderData + cipherJSON

        XCTAssertThrowsError(
            try VaultSerialization.decodeVaultFile(tamperedFile)
        ) { error in
            XCTAssertEqual(error as? VaultSerializationError, .hashMismatch)
        }
    }

    // MARK: - Truncated Ciphertext

    func testTruncatedCiphertextFails() throws {
        let key = makeVaultKey()
        let header = makeHeader()
        let payload = makeInnerPayload()

        let fileData = try VaultSerialization.encodeVaultFile(
            header: header,
            plaintext: payload,
            vaultKey: key
        )

        // Drop some bytes from the end to simulate truncation
        let truncated = fileData.dropLast(16)

        XCTAssertThrowsError(
            try VaultSerialization.decodeVaultFile(truncated)
        ) { error in
            XCTAssertEqual(error as? VaultSerializationError, .truncatedCiphertext)
        }
    }

    // MARK: - Missing Ciphertext

    func testMissingCiphertextFails() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let header = makeHeader(now: now)

        let headerData = try header.encodeToData()
        // No ciphertext appended
        XCTAssertThrowsError(
            try VaultSerialization.decodeVaultFile(headerData)
        ) { error in
            XCTAssertEqual(error as? VaultSerializationError, .missingCiphertext)
        }
    }
}
