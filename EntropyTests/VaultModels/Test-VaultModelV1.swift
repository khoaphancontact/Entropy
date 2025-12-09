//
//  Test-VaultModelV1.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultModelV1Tests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class VaultModelV1Tests: XCTestCase {

    // MARK: - Helpers

    private func makeHeader(now: Date) -> VaultFileHeader {
        let kdf = VaultKDFParamsSnapshot(
            memoryKiB: 65_536,
            iterations: 2,
            parallelism: 2,
            saltLength: 16
        )
        return VaultFileHeader.newVaultHeader(now: now, kdfParams: kdf)
    }

    private func makeSampleEntry(id: UUID, now: Date, key: ZeroizedData) throws -> VaultEntry {
        func enc(_ s: String) throws -> EncryptedField {
            let bundle = try VaultEncryption.encryptEntry(
                plaintext: Data(s.utf8),
                vaultKey: key
            )
            return EncryptedField(bundle: bundle, createdAt: now, updatedAt: now)
        }

        let username = try enc("user@example.com")
        let password = try enc("P@ssw0rd!")
        let notes = try enc("notes")

        let metadata = VaultEntryMetadata(
            lastCopiedUsername: now,
            lastCopiedPassword: nil,
            lastUsedOTP: nil,
            lastViewed: now
        )
        let encMeta = try VaultEntryMetadata.encrypt(metadata, vaultKey: key, now: now)

        return VaultEntry(
            id: id,
            title: "Example",
            domain: "example.com",
            createdAt: now,
            updatedAt: now,
            encryptedUsername: username,
            encryptedPassword: password,
            encryptedNotes: notes,
            otpBlockID: nil,
            encryptedMetadata: encMeta,
            securityInfo: nil
        )
    }

    private func makeSampleOTPBlock(id: UUID, now: Date, key: ZeroizedData) throws -> OTPBlock {
        let secret = "JBSWY3DPEHPK3PXP"
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: Data(secret.utf8),
            vaultKey: key
        )
        let field = EncryptedField(bundle: bundle, createdAt: now, updatedAt: now)

        return OTPBlock(
            id: id,
            algorithm: .sha1,
            digits: 6,
            period: 30,
            encryptedSecret: field,
            encryptedMetadata: nil
        )
    }

    private func makeKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0x42, count: 32))
    }

    // MARK: - Load / Save (encode/decode)

    func testLoadSaveRoundTrip() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let key = makeKey()

        let entryID = UUID()
        let otpID = UUID()

        let entry = try makeSampleEntry(id: entryID, now: now, key: key)
        let otpBlock = try makeSampleOTPBlock(id: otpID, now: now, key: key)

        let folder = VaultFolder(
            id: UUID(),
            name: "Unfiled",
            orderIndex: 0,
            entries: [entryID]
        )

        let model = VaultModelV1(
            schemaVersion: VaultFileHeader.currentSchemaVersion,
            createdAt: now,
            modifiedAt: now,
            entries: [entryID: entry],
            folders: [folder],
            otpBlocks: [otpID: otpBlock]
        )

        let encoder = VaultModelV1.makeJSONEncoder()
        let data = try encoder.encode(model)

        let decoder = VaultModelV1.makeJSONDecoder()
        let decoded = try decoder.decode(VaultModelV1.self, from: data)

        XCTAssertEqual(decoded.schemaVersion, model.schemaVersion)
        XCTAssertEqual(decoded.entries.count, 1)
        XCTAssertEqual(decoded.folders.count, 1)
        XCTAssertEqual(decoded.otpBlocks.count, 1)
        XCTAssertEqual(decoded.entries[entryID]?.title, "Example")
        XCTAssertEqual(decoded.folders[0].entries.first, entryID)
    }

    // MARK: - Schema version mismatch

    func testSchemaVersionMismatchThrows() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let header = makeHeader(now: now)

        // Model with a different schemaVersion
        let model = VaultModelV1(
            schemaVersion: header.schemaVersion + 1,
            createdAt: now,
            modifiedAt: now,
            entries: [:],
            folders: [],
            otpBlocks: [:]
        )

        XCTAssertThrowsError(try model.validateSchemaMatches(header: header)) { error in
            guard case let VaultModelError.schemaVersionMismatch(expected, actual) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(expected, header.schemaVersion)
            XCTAssertEqual(actual, header.schemaVersion + 1)
        }
    }

    // MARK: - Empty vault creation

    func testEmptyVaultCreation() {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let model = VaultModelV1.empty(now: now)

        XCTAssertEqual(model.schemaVersion, VaultFileHeader.currentSchemaVersion)
        XCTAssertEqual(model.entries.count, 0)
        XCTAssertEqual(model.otpBlocks.count, 0)
        XCTAssertEqual(model.folders.count, 1)

        let unfiled = model.folders[0]
        XCTAssertEqual(unfiled.name, "Unfiled")
        XCTAssertEqual(unfiled.orderIndex, 0)
        XCTAssertTrue(unfiled.entries.isEmpty)
        XCTAssertEqual(model.createdAt, now)
        XCTAssertEqual(model.modifiedAt, now)
    }
}
