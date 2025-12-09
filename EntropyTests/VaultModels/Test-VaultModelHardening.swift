//
//  Test-VaultModelHardening.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultModelHardeningTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class VaultModelHardeningTests: XCTestCase {

    // MARK: - Helpers

    private func makeBaseModel(now: Date = Date()) -> VaultModelV1 {
        VaultModelV1.empty(now: now)
    }

    private func makeEntry(id: UUID, now: Date) -> VaultEntry {
        // We don't need real ciphertext here if VaultEntry doesn't validate it
        // as part of hardening. Use minimal dummy fields.

        let dummyCiphertext = VaultCiphertext(
            ciphertext: Data(repeating: 0x01, count: 16),
            nonce: Data(repeating: 0x02, count: 12),
            associatedData: nil
        )

        let field = EncryptedField(
            bundle: dummyCiphertext,
            createdAt: now,
            updatedAt: now
        )

        return VaultEntry(
            id: id,
            title: "Entry",
            domain: "example.com",
            createdAt: now,
            updatedAt: now,
            encryptedUsername: field,
            encryptedPassword: field,
            encryptedNotes: nil,
            otpBlockID: nil,
            encryptedMetadata: nil,
            securityInfo: nil
        )
    }

    // MARK: - Missing entry detection (folder references non-existent entry)

    func testMissingEntryDetection() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        var model = makeBaseModel(now: now)

        // Add one existing entry
        let existingID = UUID()
        let entry = makeEntry(id: existingID, now: now)
        model.entries[existingID] = entry

        // Folder references one valid and one invalid entry ID
        let missingID = UUID()
        let folder = VaultFolder(
            id: UUID(),
            name: "Unfiled",
            orderIndex: 0,
            entries: [existingID, missingID]
        )
        model.folders = [folder]

        XCTAssertThrowsError(try model.validateHardening()) { error in
            guard case let VaultHardeningError.folderReferencesMissingEntry(folderID, entryID) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(folderID, folder.id)
            XCTAssertEqual(entryID, missingID)
        }
    }

    // MARK: - Orphaned entry detection (entry not in any folder)

    func testOrphanedEntryDetection() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        var model = makeBaseModel(now: now)

        let orphanID = UUID()
        let entry = makeEntry(id: orphanID, now: now)
        model.entries[orphanID] = entry

        // Unfiled folder exists but doesn't reference the entry
        let folder = VaultFolder(
            id: UUID(),
            name: "Unfiled",
            orderIndex: 0,
            entries: [] // no entries
        )
        model.folders = [folder]

        XCTAssertThrowsError(try model.validateHardening()) { error in
            guard case let VaultHardeningError.orphanedEntry(entryID) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(entryID, orphanID)
        }
    }

    // MARK: - Invalid UUID formats (mismatched dictionary key vs. entry.id)

    func testInvalidUUIDFormatDetectionViaMismatchedEntryKey() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        var model = makeBaseModel(now: now)

        let keyID = UUID()
        let differentID = UUID()

        // Entry with id different from dictionary key
        let entry = makeEntry(id: differentID, now: now)
        model.entries[keyID] = entry

        // Still need Unfiled folder so other checks don't fire first
        let folder = VaultFolder(
            id: UUID(),
            name: "Unfiled",
            orderIndex: 0,
            entries: [] // no references
        )
        model.folders = [folder]

        XCTAssertThrowsError(try model.validateHardening()) { error in
            guard case let VaultHardeningError.mismatchedEntryKey(expectedKey, actualID) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(expectedKey, keyID)
            XCTAssertEqual(actualID, differentID)
        }
    }

    // MARK: - Missing Unfiled folder

    func testMissingUnfiledFolderFails() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        var model = makeBaseModel(now: now)
        // Overwrite folders with none named "Unfiled"
        model.folders = [
            VaultFolder(
                id: UUID(),
                name: "Personal",
                orderIndex: 0,
                entries: []
            )
        ]

        XCTAssertThrowsError(try model.validateHardening()) { error in
            XCTAssertEqual(error as? VaultHardeningError, .missingUnfiledFolder)
        }
    }

    // MARK: - Invalid timestamps

    func testInvalidEntryTimestampsFails() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        var model = makeBaseModel(now: now)

        let id = UUID()
        var entry = makeEntry(id: id, now: now)

        // Force updatedAt earlier than createdAt
        let earlier = now.addingTimeInterval(-60)
        entry = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: now,
            updatedAt: earlier,
            encryptedUsername: entry.encryptedUsername,
            encryptedPassword: entry.encryptedPassword,
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: entry.encryptedMetadata,
            securityInfo: entry.securityInfo
        )

        model.entries[id] = entry

        // Keep Unfiled folder to avoid missing-folder error first
        let folder = VaultFolder(
            id: UUID(),
            name: "Unfiled",
            orderIndex: 0,
            entries: [id]
        )
        model.folders = [folder]

        XCTAssertThrowsError(try model.validateHardening()) { error in
            guard case let VaultHardeningError.invalidEntryTimestamps(entryID) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(entryID, id)
        }
    }
}
