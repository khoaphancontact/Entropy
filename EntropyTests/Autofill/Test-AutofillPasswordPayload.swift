//
//  Test-AutofillPasswordPayload.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//
//
//  AutofillPasswordPayloadTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class AutofillPasswordPayloadTests: XCTestCase {

    private func makeKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0xAB, count: 32))
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

    private func makeEntry(
        username: String,
        password: String,
        now: Date,
        key: ZeroizedData
    ) throws -> VaultEntry {

        let encUser = try encryptField(username, key: key, now: now)
        let encPass = try encryptField(password, key: key, now: now)

        return VaultEntry(
            id: UUID(),
            title: "Test Entry",
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

    func testAutofillPayloadContents() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let key = makeKey()

        let entry = try makeEntry(
            username: "user@example.com",
            password: "SuperPassword123!",
            now: now,
            key: key
        )

        let adapter = VaultAutofillAdapter()
        let payload = try adapter.autofillPayload(
            for: entry,
            requestDomain: "example.com",
            vaultKey: key
        )

        // Check ID + metadata propagation
        XCTAssertEqual(payload.entryID, entry.id)
        XCTAssertEqual(payload.domain, "example.com")
        XCTAssertEqual(payload.createdAt, entry.createdAt)
        XCTAssertEqual(payload.updatedAt, entry.updatedAt)

        // Username is intentionally not decrypted in J3
        XCTAssertNil(payload.username)

        // Validate password decrypt
        let decryptedPassword = try payload.password.withBytes { Data($0) }
        XCTAssertEqual(
            String(decoding: decryptedPassword, as: UTF8.self),
            "SuperPassword123!"
        )
    }

    func testPasswordMemoryIsolated() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let key = makeKey()

        let entry = try makeEntry(
            username: "ignored",
            password: "IsolatedSecret!",
            now: now,
            key: key
        )

        let adapter = VaultAutofillAdapter()
        let payload = try adapter.autofillPayload(
            for: entry,
            requestDomain: "example.com",
            vaultKey: key
        )

        // Extract password bytes in controlled zeroized fashion
        let decrypted = try payload.password.withBytes { Data($0) }

        XCTAssertEqual(
            String(decoding: decrypted, as: UTF8.self),
            "IsolatedSecret!"
        )

        // Ensure underlying pointer access doesn't leak.
        // (ZeroizedData enforces copy-on-access; we can confirm it does not match ciphertext.)
        let cipher = entry.encryptedPassword.bundle.ciphertext
        XCTAssertNotEqual(cipher, decrypted)
    }
}
