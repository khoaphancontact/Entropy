//
//  Test-VaultEntry+PartialDecrypt.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/9/25.
//

//
//  VaultEntryPartialDecryptTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class VaultEntryPartialDecryptTests: XCTestCase {

    // MARK: - Helpers

    private func makeKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0x42, count: 32))
    }

    private func encryptField(
        _ plaintext: String,
        key: ZeroizedData,
        now: Date
    ) throws -> EncryptedField {
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: Data(plaintext.utf8),
            vaultKey: key
        )
        return EncryptedField(
            bundle: bundle,
            createdAt: now,
            updatedAt: now
        )
    }

    private func makeEntryWithPassword(
        password: String,
        now: Date,
        key: ZeroizedData
    ) throws -> VaultEntry {
        let encUser = try encryptField("username", key: key, now: now)
        let encPass = try encryptField(password, key: key, now: now)

        return VaultEntry(
            id: UUID(),
            title: "Example",
            domain: "example.com",
            createdAt: now,
            updatedAt: now,
            encryptedUsername: encUser,
            encryptedPassword: encPass,
            encryptedNotes: nil,
            otpBlockID: nil,
            encryptedMetadata: nil,
            securityInfo: nil
        )
    }

    // MARK: - password decrypt succeeds

    func testPasswordDecryptSucceeds() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let key = makeKey()
        let entry = try makeEntryWithPassword(password: "MySecret123", now: now, key: key)

        let plaintext = try entry.decryptPasswordOnly(vaultKey: key)
        let data = try plaintext.withBytes { Data($0) }

        XCTAssertEqual(String(data: data, encoding: .utf8), "MySecret123")
    }

    // MARK: - username stays encrypted

    func testUsernameRemainsEncrypted() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let key = makeKey()
        let entry = try makeEntryWithPassword(password: "abc123", now: now, key: key)

        // Take a snapshot of username ciphertext
        let usernameField = entry.encryptedUsername
        let cipherBefore = usernameField.bundle.ciphertext

        _ = try entry.decryptPasswordOnly(vaultKey: key)

        let cipherAfter = usernameField.bundle.ciphertext
        XCTAssertEqual(cipherBefore, cipherAfter)
    }

    // MARK: - corrupted ciphertext throws

    func testCorruptedPasswordCiphertextThrows() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let key = makeKey()
        var entry = try makeEntryWithPassword(password: "abc123", now: now, key: key)

        // Corrupt the password ciphertext by flipping a byte
        var corruptedBundle = entry.encryptedPassword.bundle
        var corruptedCipher = corruptedBundle.ciphertext
        corruptedCipher[0] ^= 0xFF

        corruptedBundle = VaultCiphertext(
            ciphertext: corruptedCipher,
            nonce: corruptedBundle.nonce,
            associatedData: corruptedBundle.associatedData
        )

        entry = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: entry.encryptedUsername,
            encryptedPassword: EncryptedField(
                bundle: corruptedBundle,
                createdAt: entry.encryptedPassword.createdAt,
                updatedAt: entry.encryptedPassword.updatedAt
            ),
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: entry.encryptedMetadata,
            securityInfo: entry.securityInfo
        )

        XCTAssertThrowsError(
            try entry.decryptPasswordOnly(vaultKey: key)
        ) { error in
            // From VaultEncryption.decryptEntry
            XCTAssertTrue(error is VaultEncryptionError)
        }
    }
}
