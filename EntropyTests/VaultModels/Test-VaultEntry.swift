//
//  VaultEntryTests.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//


//
//  VaultEntryTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class VaultEntryTests: XCTestCase {

    // MARK: - Helpers

    private func makeVaultKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0x11, count: 32))
    }

    private func enc(
        _ string: String,
        vaultKey: ZeroizedData,
        date: Date
    ) throws -> EncryptedField {
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: Data(string.utf8),
            vaultKey: vaultKey
        )
        return EncryptedField(bundle: bundle, createdAt: date, updatedAt: date)
    }

    private func sampleEntry() throws -> (VaultEntry, ZeroizedData, Date) {
        let key = makeVaultKey()
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        let encUser = try enc("user@example.com", vaultKey: key, date: now)
        let encPass = try enc("P@ssw0rd!",        vaultKey: key, date: now)
        let encNotes = try enc("secure-notes",    vaultKey: key, date: now)

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
            otpBlockID: nil,
            encryptedMetadata: encMeta,
            securityInfo: nil
        )

        return (entry, key, now)
    }

    // MARK: - Codable

    func testEncodeDecodeRoundTrip() throws {
        let (entry, _, _) = try sampleEntry()

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(entry)
        let decoded = try decoder.decode(VaultEntry.self, from: data)

        XCTAssertEqual(decoded.id, entry.id)
        XCTAssertEqual(decoded.title, entry.title)
        XCTAssertEqual(decoded.domain, entry.domain)
        XCTAssertEqual(decoded.createdAt, entry.createdAt)
        XCTAssertEqual(decoded.updatedAt, entry.updatedAt)
    }

    // MARK: - Validation

    func testMissingCiphertextFailsValidation() throws {
        let (entry, _, _) = try sampleEntry()

        // Break username ciphertext
        let brokenBundle = VaultCiphertext(
            ciphertext: Data(), // invalid
            nonce: entry.encryptedUsername.bundle.nonce,
            associatedData: nil
        )

        let brokenField = EncryptedField(
            bundle: brokenBundle,
            createdAt: entry.encryptedUsername.createdAt,
            updatedAt: entry.encryptedUsername.updatedAt
        )

        let badEntry = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: brokenField,
            encryptedPassword: entry.encryptedPassword,
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: entry.encryptedMetadata,
            securityInfo: nil
        )

        XCTAssertThrowsError(try badEntry.validate()) { error in
            XCTAssertEqual(error as? VaultEntryError, .invalidCiphertext)
        }
    }

    func testInvalidNonceFailsValidation() throws {
        let (entry, _, _) = try sampleEntry()

        var wrongNonce = Data(repeating: 0x00, count: 8) // should be 12 bytes
        let corrupt = VaultCiphertext(
            ciphertext: entry.encryptedUsername.bundle.ciphertext,
            nonce: wrongNonce,
            associatedData: nil
        )

        let corruptField = EncryptedField(
            bundle: corrupt,
            createdAt: entry.encryptedUsername.createdAt,
            updatedAt: entry.encryptedUsername.updatedAt
        )

        let badEntry = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: corruptField,
            encryptedPassword: entry.encryptedPassword,
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: entry.encryptedMetadata,
            securityInfo: nil
        )

        XCTAssertThrowsError(try badEntry.validate()) { error in
            XCTAssertEqual(error as? VaultEntryError, .invalidCiphertext)
        }
    }

    // MARK: - Partial Decrypt

    func testPartialDecryptWorks() throws {
        let (entry, key, _) = try sampleEntry()

        let u = try entry.decryptUsername(vaultKey: key)
        let p = try entry.decryptPassword(vaultKey: key)
        let n = try entry.decryptNotes(vaultKey: key)

        XCTAssertEqual(
            String(data: try u.withBytes { Data($0) }, encoding: .utf8),
            "user@example.com"
        )

        XCTAssertEqual(
            String(data: try p.withBytes { Data($0) }, encoding: .utf8),
            "P@ssw0rd!"
        )

        XCTAssertEqual(
            String(data: try n.withBytes { Data($0) }, encoding: .utf8),
            "secure-notes"
        )
    }

    // MARK: - Metadata

    func testMetadataDecryptRoundTrip() throws {
        let (entry, key, now) = try sampleEntry()

        let parsed = try entry.decryptMetadata(vaultKey: key)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.lastCopiedUsername, now)
        XCTAssertEqual(parsed?.lastViewed, now)
    }

    func testMetadataCorruptionFails() throws {
        let (entry, key, _) = try sampleEntry()

        guard let metadataField = entry.encryptedMetadata else {
            XCTFail("missing metadata field"); return
        }

        // Flip a byte in ciphertext
        var corrupted = metadataField.bundle
        var data = corrupted.ciphertext
        data[0] ^= 0xFF
        corrupted = VaultCiphertext(
            ciphertext: data,
            nonce: corrupted.nonce,
            associatedData: corrupted.associatedData
        )

        let corruptField = EncryptedField(
            bundle: corrupted,
            createdAt: metadataField.createdAt,
            updatedAt: metadataField.updatedAt
        )

        let badEntry = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: entry.encryptedUsername,
            encryptedPassword: entry.encryptedPassword,
            encryptedNotes: entry.encryptedNotes,
            otpBlockID: entry.otpBlockID,
            encryptedMetadata: corruptField,
            securityInfo: nil
        )

        XCTAssertThrowsError(try badEntry.decryptMetadata(vaultKey: key)) { error in
            XCTAssertEqual(error as? VaultEntryError, .metadataDecodeFailed)
        }
    }
}
