//
//  Test-DecryptedVault.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  DecryptedVaultTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class DecryptedVaultTests: XCTestCase {

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

    private func makeSimpleDecryptedVault() throws -> DecryptedVault {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let header = makeHeader(now: now)

        let vaultKey = ZeroizedData(copying: Data(repeating: 0x55, count: 32))

        // Minimal entry with dummy ZeroizedData (no OTP)
        let username = ZeroizedData(copying: Data("u".utf8))
        let password = ZeroizedData(copying: Data("p".utf8))
        let notes = ZeroizedData(copying: Data("n".utf8))

        let decryptedEntry = DecryptedVaultEntry(
            id: UUID(),
            title: "Entry",
            domain: "example.com",
            createdAt: now,
            updatedAt: now,
            username: username,
            password: password,
            notes: notes,
            otpSecret: nil,
            metadata: nil,
            securityInfo: nil
        )

        let folder = VaultFolder(
            name: "Unfiled",
            orderIndex: 0,
            entries: [decryptedEntry.id]
        )

        return DecryptedVault(
            header: header,
            vaultKey: vaultKey,
            entries: [decryptedEntry],
            folders: [folder]
        )
    }

    // MARK: - Structure

    func testDecryptedVaultHoldsHeaderAndStructure() throws {
        let vault = try makeSimpleDecryptedVault()

        XCTAssertEqual(vault.folders.count, 1)
        XCTAssertEqual(vault.entries.count, 1)
        XCTAssertEqual(vault.folders[0].entries.first, vault.entries[0].id)

        // header sanity
        XCTAssertEqual(vault.header.vaultVersion, VaultFileHeader.currentVaultVersion)
        XCTAssertEqual(vault.header.schemaVersion, VaultFileHeader.currentSchemaVersion)
    }

    // MARK: - Wipe behavior

    func testWipeSensitiveDataWipesVaultKeyAndEntries() throws {
        let vault = try makeSimpleDecryptedVault()

        // Ensure key is readable before wipe
        _ = try vault.vaultKey.withBytes { _ in }

        // Ensure entry password readable before wipe
        let entry = vault.entries[0]
        _ = try entry.password.withBytes { _ in }

        vault.wipeSensitiveData()

        // Key should be wiped
        XCTAssertThrowsError(
            try vault.vaultKey.withBytes { _ in }
        ) { error in
            XCTAssertEqual(error as? ZeroizedData.ZeroizedDataError, .wiped)
        }

        // Entry password should be wiped
        XCTAssertThrowsError(
            try entry.password.withBytes { _ in }
        ) { error in
            XCTAssertEqual(error as? ZeroizedData.ZeroizedDataError, .wiped)
        }
    }
}
