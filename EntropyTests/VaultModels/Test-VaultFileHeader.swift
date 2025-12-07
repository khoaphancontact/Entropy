//
//  Test-VaultFileHeader.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  VaultFileHeaderTests.swift
//  EntropyVaultModelsTests
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

import XCTest
@testable import Entropy   // adjust to your module name

final class VaultFileHeaderTests: XCTestCase {

    // MARK: - Helpers

    private func makeParams() -> VaultKDFParamsSnapshot {
        return VaultKDFParamsSnapshot(
            algorithm: .argon2id,
            memoryKiB: 65_536,
            iterations: 2,
            parallelism: 2,
            saltLength: 16
        )
    }

    private func stableDate() -> Date {
        return Date(timeIntervalSince1970: 1_750_000_000)
    }

    // MARK: - Round Trip

    func testRoundTripEncodingDecoding() throws {
        let now = stableDate()
        let header = VaultFileHeader(
            vaultVersion: VaultFileHeader.currentVaultVersion,
            schemaVersion: VaultFileHeader.currentSchemaVersion,
            createdAt: now,
            modifiedAt: now,
            encryptionMethod: .aes256GCM,
            kdfParams: makeParams(),
            integrityHash: Data(repeating: 0, count: VaultFileHeader.integrityHashLength)
        )

        let encoded = try header.encodeToData()
        let decoded = try VaultFileHeader.decode(from: encoded)

        XCTAssertEqual(decoded.vaultVersion, header.vaultVersion)
        XCTAssertEqual(decoded.schemaVersion, header.schemaVersion)
        XCTAssertEqual(decoded.createdAt, header.createdAt)
        XCTAssertEqual(decoded.modifiedAt, header.modifiedAt)
        XCTAssertEqual(decoded.encryptionMethod, header.encryptionMethod)
        XCTAssertEqual(decoded.kdfParams, header.kdfParams)
        XCTAssertEqual(decoded.integrityHash, header.integrityHash)
    }

    // MARK: - Structural Failures

    func testEmptyDataRejects() {
        XCTAssertThrowsError(try VaultFileHeader.decode(from: Data())) { error in
            XCTAssertEqual(error as? VaultFileHeaderError, .emptyData)
        }
    }

    func testTruncatedDataRejects() {
        // Less than magic + headerVersion + length
        let truncated = Data([0x45, 0x4E, 0x54]) // "ENT"
        XCTAssertThrowsError(try VaultFileHeader.decode(from: truncated)) { error in
            XCTAssertEqual(error as? VaultFileHeaderError, .truncatedData)
        }
    }

    func testInvalidMagicRejects() throws {
        var raw = Data()
        raw.append("WRNG".data(using: .utf8)!)   // bad magic
        raw.append(VaultFileHeader.headerFormatVersion)
        var len: UInt32 = UInt32(2).bigEndian
        raw.append(Data(bytes: &len, count: MemoryLayout<UInt32>.size))
        raw.append(Data([0x7B, 0x7D])) // "{}"

        XCTAssertThrowsError(try VaultFileHeader.decode(from: raw)) { error in
            XCTAssertEqual(error as? VaultFileHeaderError, .invalidMagic)
        }
    }

    func testUnsupportedHeaderFormatVersionRejects() throws {
        let header = VaultFileHeader.newVaultHeader(
            now: stableDate(),
            kdfParams: makeParams()
        )
        var encoded = try header.encodeToData()

        // Flip header format version byte
        let index = VaultFileHeader.magic.count
        encoded[index] = VaultFileHeader.headerFormatVersion &+ 1

        XCTAssertThrowsError(try VaultFileHeader.decode(from: encoded)) { error in
            if case let VaultFileHeaderError.unsupportedHeaderFormatVersion(v) = error {
                XCTAssertEqual(v, VaultFileHeader.headerFormatVersion &+ 1)
            } else {
                XCTFail("wrong error: \(error)")
            }
        }
    }

    // MARK: - Version Mismatch

    func testUnsupportedVaultVersionRejects() throws {
        let now = stableDate()
        let header = VaultFileHeader(
            vaultVersion: VaultFileHeader.currentVaultVersion + 1,
            schemaVersion: VaultFileHeader.currentSchemaVersion,
            createdAt: now,
            modifiedAt: now,
            encryptionMethod: .aes256GCM,
            kdfParams: makeParams(),
            integrityHash: Data(repeating: 0, count: VaultFileHeader.integrityHashLength)
        )

        let encoded = try header.encodeToData()

        XCTAssertThrowsError(try VaultFileHeader.decode(from: encoded)) { error in
            if case let VaultFileHeaderError.unsupportedVaultVersion(v) = error {
                XCTAssertEqual(v, VaultFileHeader.currentVaultVersion + 1)
            } else {
                XCTFail("wrong error: \(error)")
            }
        }
    }

    // MARK: - Malformed JSON

    func testMalformedHeaderBodyRejects() throws {
        let badJSON = """
        { "vaultVersion": 1 }
        """.data(using: .utf8)!

        var raw = Data()
        raw.append(VaultFileHeader.magic)
        raw.append(VaultFileHeader.headerFormatVersion)

        var len = UInt32(badJSON.count).bigEndian
        raw.append(Data(bytes: &len, count: MemoryLayout<UInt32>.size))
        raw.append(badJSON)

        XCTAssertThrowsError(try VaultFileHeader.decode(from: raw)) { error in
            XCTAssertEqual(error as? VaultFileHeaderError, .malformedHeaderBody)
        }
    }

    // MARK: - Integrity Hash

    func testInvalidIntegrityHashLengthRejects() throws {
        let now = stableDate()
        let badHash = Data(repeating: 0, count: VaultFileHeader.integrityHashLength - 1)

        let header = VaultFileHeader(
            vaultVersion: VaultFileHeader.currentVaultVersion,
            schemaVersion: VaultFileHeader.currentSchemaVersion,
            createdAt: now,
            modifiedAt: now,
            encryptionMethod: .aes256GCM,
            kdfParams: makeParams(),
            integrityHash: badHash
        )

        let encoded = try header.encodeToData()

        XCTAssertThrowsError(try VaultFileHeader.decode(from: encoded)) { error in
            if case let VaultFileHeaderError.invalidIntegrityHashLength(expected, actual) = error {
                XCTAssertEqual(expected, VaultFileHeader.integrityHashLength)
                XCTAssertEqual(actual, VaultFileHeader.integrityHashLength - 1)
            } else {
                XCTFail("wrong error: \(error)")
            }
        }
    }
}
