//
//  Test-VaultAutofillAdapter.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/9/25.
//
//
//  VaultAutofillAdapterIntegratedTests.swift
//

import XCTest
@testable import Entropy

final class VaultAutofillAdapterIntegratedTests: XCTestCase {

    private func makeKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0x33, count: 32))
    }

    private func encryptField(_ s: String, key: ZeroizedData, now: Date) throws -> EncryptedField {
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: Data(s.utf8),
            vaultKey: key
        )
        return EncryptedField(bundle: bundle, createdAt: now, updatedAt: now)
    }

    private func makeEntry(now: Date, key: ZeroizedData) throws -> VaultEntry {
        let encUser = try encryptField("user@example.com", key: key, now: now)
        let encPass = try encryptField("SuperSecret!", key: key, now: now)

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

    // MARK: - Success

    func testAutofillPipelineSuccess() throws {
        let now = Date()
        let key = makeKey()
        let entry = try makeEntry(now: now, key: key)

        let adapter = VaultAutofillAdapter()
        let payload = try adapter.autofillPayload(
            for: entry,
            requestDomain: "example.com",
            vaultKey: key
        )

        XCTAssertEqual(payload.entryID, entry.id)
        XCTAssertEqual(payload.domain, "example.com")

        let plaintext = try payload.password.withBytes { Data($0) }
        XCTAssertEqual(String(data: plaintext, encoding: .utf8), "SuperSecret!")
    }

    // MARK: - Wrong domain

    func testWrongDomainRejects() throws {
        let now = Date()
        let key = makeKey()
        let entry = try makeEntry(now: now, key: key)
        let adapter = VaultAutofillAdapter()

        XCTAssertThrowsError(
            try adapter.autofillPayload(
                for: entry,
                requestDomain: "evil.com",
                vaultKey: key
            )
        ) { error in
            XCTAssertEqual(error as? AutofillAdapterError, .domainMismatch)
        }
    }

    // MARK: - Missing password / malformed ciphertext

    func testTamperedEntryRejectedBeforeDecrypt() throws {
        let now = Date()
        let key = makeKey()
        var entry = try makeEntry(now: now, key: key)

        // Tamper password ciphertext
        var bad = entry.encryptedPassword.bundle
        var cipher = bad.ciphertext
        cipher[0] ^= 0xFF // flip a byte
        bad = VaultCiphertext(
            ciphertext: cipher,
            nonce: bad.nonce,
            associatedData: bad.associatedData
        )

        entry = VaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            encryptedUsername: entry.encryptedUsername,
            encryptedPassword: EncryptedField(
                bundle: bad,
                createdAt: now,
                updatedAt: now
            ),
            encryptedNotes: nil,
            otpBlockID: nil,
            encryptedMetadata: nil,
            securityInfo: nil
        )

        let adapter = VaultAutofillAdapter()

        XCTAssertThrowsError(
            try adapter.autofillPayload(
                for: entry,
                requestDomain: "example.com",
                vaultKey: key
            )
        ) { error in
            // Tampering is caught during decrypt, not validation
            XCTAssertTrue(error is VaultEncryptionError)
        }
    }
}
