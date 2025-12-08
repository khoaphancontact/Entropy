//
//  Test-DecryptedVaultEntry.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  DecryptedVaultEntryTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class DecryptedVaultEntryTests: XCTestCase {

    // MARK: - Helpers

    private func makeVaultKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0x44, count: 32))
    }

    private func encField(
        _ string: String,
        key: ZeroizedData,
        date: Date
    ) throws -> EncryptedField {
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: Data(string.utf8),
            vaultKey: key
        )
        return EncryptedField(bundle: bundle, createdAt: date, updatedAt: date)
    }

    /// Build a VaultEntry + OTPBlock pair with known plaintext.
    private func makeEncryptedModels() throws -> (VaultEntry, OTPBlock, ZeroizedData, Date) {
        let key = makeVaultKey()
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        let usernamePlain = "user@example.com"
        let passwordPlain = "P@ssw0rd!"
        let notesPlain = "secret-notes"
        let otpSecretPlain = "JBSWY3DPEHPK3PXP"

        let encUser = try encField(usernamePlain, key: key, date: now)
        let encPass = try encField(passwordPlain, key: key, date: now)
        let encNotes = try encField(notesPlain, key: key, date: now)

        // OTP secret field
        let otpEnc = try encField(otpSecretPlain, key: key, date: now)
        let otpBlock = OTPBlock(
            id: UUID(),
            algorithm: .sha1,
            digits: 6,
            period: 30,
            encryptedSecret: otpEnc,
            encryptedMetadata: nil
        )

        let metadata = VaultEntryMetadata(
            lastCopiedUsername: now,
            lastCopiedPassword: nil,
            lastUsedOTP: nil,
            lastViewed: now
        )
        let encMeta = try VaultEntryMetadata.encrypt(metadata, vaultKey: key, now: now)

        let entry = VaultEntry(
            id: UUID(),
            title: "Example",
            domain: "example.com",
            createdAt: now,
            updatedAt: now,
            encryptedUsername: encUser,
            encryptedPassword: encPass,
            encryptedNotes: encNotes,
            otpBlockID: otpBlock.id,
            encryptedMetadata: encMeta,
            securityInfo: nil
        )

        return (entry, otpBlock, key, now)
    }

    // MARK: - Mapping correctness

    func testDecryptedEntryHoldsCorrectData() throws {
        let (entry, otpBlock, key, now) = try makeEncryptedModels()

        let decrypted = try DecryptedVaultEntry.from(
            entry: entry,
            otpBlock: otpBlock,
            vaultKey: key
        )

        // Username
        let username = String(
            data: try decrypted.username.withBytes { Data($0) },
            encoding: .utf8
        )
        XCTAssertEqual(username, "user@example.com")

        // Password
        let password = String(
            data: try decrypted.password.withBytes { Data($0) },
            encoding: .utf8
        )
        XCTAssertEqual(password, "P@ssw0rd!")

        // Notes
        let notes = String(
            data: try decrypted.notes!.withBytes { Data($0) },
            encoding: .utf8
        )
        XCTAssertEqual(notes, "secret-notes")

        // OTP Secret
        let otpSecret = String(
            data: try decrypted.otpSecret!.withBytes { Data($0) },
            encoding: .utf8
        )
        XCTAssertEqual(otpSecret, "JBSWY3DPEHPK3PXP")

        // Metadata
        XCTAssertNotNil(decrypted.metadata)
        XCTAssertEqual(decrypted.metadata?.lastCopiedUsername, now)
        XCTAssertEqual(decrypted.metadata?.lastViewed, now)
    }

    // MARK: - Wipe behavior

    func testWipeSensitiveDataWipesZeroizedData() throws {
        let (entry, otpBlock, key, _) = try makeEncryptedModels()
        let decrypted = try DecryptedVaultEntry.from(
            entry: entry,
            otpBlock: otpBlock,
            vaultKey: key
        )

        // Ensure we can read before wipe
        _ = try decrypted.password.withBytes { _ in }

        // Wipe and ensure future reads fail
        decrypted.wipeSensitiveData()

        XCTAssertThrowsError(
            try decrypted.password.withBytes { _ in }
        ) { error in
            XCTAssertEqual(error as? ZeroizedData.ZeroizedDataError, .wiped)
        }
    }
}
