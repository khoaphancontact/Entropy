//
//  Test-VaultAutofillAdapter+Validation.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/9/25.
//

//
//  VaultAutofillAdapterValidationTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class VaultAutofillAdapterValidationTests: XCTestCase {

    private func makeKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0x44, count: 32))
    }

    private func encrypt(_ text: String, key: ZeroizedData, now: Date) throws -> EncryptedField {
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: Data(text.utf8),
            vaultKey: key
        )
        return EncryptedField(bundle: bundle, createdAt: now, updatedAt: now)
    }

    private func makeValidEntry(now: Date, key: ZeroizedData) throws -> VaultEntry {
        let encUser = try encrypt("u", key: key, now: now)
        let encPass = try encrypt("p", key: key, now: now)

        return VaultEntry(
            id: UUID(),
            title: "Test",
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

    // MARK: - Success

    func testValidationSucceedsForValidEntry() throws {
        let now = Date()
        let key = makeKey()
        let entry = try makeValidEntry(now: now, key: key)

        let adapter = VaultAutofillAdapter()

        // Should not throw
        XCTAssertNoThrow(
            try adapter.validateEntryBeforeAutofill(entry)
        )
    }

    // MARK: - Missing password ciphertext → reject

    func testMissingPasswordCiphertextRejects() throws {
        let now = Date()
        let key = makeKey()
        let entry = try makeValidEntry(now: now, key: key)

        // Replace encryptedPassword with invalid empty ciphertext
        let broken = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: entry.encryptedUsername,
            encryptedPassword: EncryptedField(
                bundle: VaultCiphertext(
                    ciphertext: Data(), // EMPTY!
                    nonce: Data(repeating: 1, count: 12),
                    associatedData: nil
                ),
                createdAt: now,
                updatedAt: now
            ),
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: entry.encryptedMetadata,
            securityInfo: entry.securityInfo
        )

        let adapter = VaultAutofillAdapter()

        XCTAssertThrowsError(
            try adapter.validateEntryBeforeAutofill(broken)
        ) { error in
            XCTAssertEqual(error as? AutofillValidationError, .invalidCiphertext)
        }
    }

    // MARK: - Wrong nonce length → reject

    func testInvalidNonceRejects() throws {
        let now = Date()
        let key = makeKey()
        let entry = try makeValidEntry(now: now, key: key)

        var badBundle = entry.encryptedPassword.bundle
        badBundle = VaultCiphertext(
            ciphertext: badBundle.ciphertext,
            nonce: Data([0x00]),  // INVALID nonce
            associatedData: nil
        )

        let brokenEntry = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: entry.encryptedUsername,
            encryptedPassword: EncryptedField(
                bundle: badBundle,
                createdAt: now,
                updatedAt: now
            ),
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: entry.encryptedMetadata,
            securityInfo: entry.securityInfo
        )

        let adapter = VaultAutofillAdapter()

        XCTAssertThrowsError(
            try adapter.validateEntryBeforeAutofill(brokenEntry)
        ) { error in
            XCTAssertEqual(error as? AutofillValidationError, .invalidNonce)
        }
    }

    // MARK: - Wrong ciphertext / tag length → reject

    func testInvalidTagRejects() throws {
        let now = Date()
        let key = makeKey()
        let entry = try makeValidEntry(now: now, key: key)

        var bundle = entry.encryptedPassword.bundle
        bundle = VaultCiphertext(
            ciphertext: Data([0xFF]),   // 1 byte → not enough for tag
            nonce: bundle.nonce,
            associatedData: nil
        )

        let broken = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: entry.encryptedUsername,
            encryptedPassword: EncryptedField(
                bundle: bundle,
                createdAt: now,
                updatedAt: now
            ),
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: entry.encryptedMetadata,
            securityInfo: entry.securityInfo
        )

        let adapter = VaultAutofillAdapter()

        XCTAssertThrowsError(
            try adapter.validateEntryBeforeAutofill(broken)
        ) { error in
            XCTAssertEqual(error as? AutofillValidationError, .invalidTag)
        }
    }

    // MARK: - Tamper ciphertext → still caught by structural validation (no decrypt)

    func testTamperedCiphertextRejected() throws {
        let now = Date()
        let key = makeKey()
        var entry = try makeValidEntry(now: now, key: key)

        // Flip a byte to simulate tampering
        var tamperedBundle = entry.encryptedPassword.bundle
        var cipher = tamperedBundle.ciphertext
        cipher[0] ^= 0xFF
        tamperedBundle = VaultCiphertext(
            ciphertext: cipher,
            nonce: tamperedBundle.nonce,
            associatedData: tamperedBundle.associatedData
        )

        entry = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: entry.encryptedUsername,
            encryptedPassword: EncryptedField(
                bundle: tamperedBundle,
                createdAt: now,
                updatedAt: now
            ),
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: entry.encryptedMetadata,
            securityInfo: entry.securityInfo
        )

        let adapter = VaultAutofillAdapter()

        // Should fail before decrypt step
        XCTAssertNoThrow(try adapter.validateEntryBeforeAutofill(entry))

        // But decrypt will later fail — J2 covers that behavior.
        XCTAssertThrowsError(
            try entry.decryptPasswordOnly(vaultKey: key)
        )
    }
}
