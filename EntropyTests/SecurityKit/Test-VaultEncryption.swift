//
//  Test-VaultEncryption.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

import XCTest
@testable import Entropy

final class VaultEncryptionTests: XCTestCase {

    /// Generate a secure random 32-byte vault key wrapped in ZeroizedData
    private func makeVaultKey() throws -> ZeroizedData {
        let key = try SecureRandom.bytes(count: 32)
        return ZeroizedData(copying: key)
    }

    // MARK: - Basic Round Trip

    func testEncryptDecryptRoundTrip() throws {
        let key = try makeVaultKey()
        let plaintext = "supersecretpassword123".data(using: .utf8)!

        let encrypted = try VaultEncryption.encryptEntry(
            plaintext: plaintext,
            vaultKey: key,
            associatedData: nil
        )

        XCTAssertFalse(encrypted.ciphertext.isEmpty)
        XCTAssertEqual(encrypted.nonce.count, 12)

        let decrypted = try VaultEncryption.decryptEntry(encrypted, vaultKey: key)
        XCTAssertEqual(decrypted.dataValue, plaintext)
    }

    // MARK: - Wrong Key Fails

    func testWrongKeyFails() throws {
        let correctKey = try makeVaultKey()
        let wrongKey = try makeVaultKey()
        let plaintext = "admin123".data(using: .utf8)!

        let encrypted = try VaultEncryption.encryptEntry(plaintext: plaintext, vaultKey: correctKey)

        XCTAssertThrowsError(
            try VaultEncryption.decryptEntry(encrypted, vaultKey: wrongKey)
        ) { error in
            guard case VaultEncryptionError.decryptionFailure = error else {
                XCTFail("Expected decryptionFailure, got \(error)")
                return
            }
        }
    }

    // MARK: - Tampered Ciphertext

    func testTamperedCiphertextFails() throws {
        let key = try makeVaultKey()
        let plaintext = "hello world".data(using: .utf8)!

        let encrypted = try VaultEncryption.encryptEntry(plaintext: plaintext, vaultKey: key)

        var corrupted = encrypted.ciphertext
        XCTAssertFalse(corrupted.isEmpty)

        // Flip first byte
        corrupted[corrupted.startIndex] ^= 0xFF

        let tampered = VaultCiphertext(
            ciphertext: corrupted,
            nonce: encrypted.nonce,
            associatedData: nil
        )

        XCTAssertThrowsError(
            try VaultEncryption.decryptEntry(tampered, vaultKey: key)
        ) { error in
            guard case VaultEncryptionError.decryptionFailure = error else {
                XCTFail("Expected decryptionFailure, got \(error)")
                return
            }
        }
    }

    // MARK: - Tampered Nonce

    func testTamperedNonceFails() throws {
        let key = try makeVaultKey()
        let plaintext = "nonce sensitive data".data(using: .utf8)!

        let encrypted = try VaultEncryption.encryptEntry(plaintext: plaintext, vaultKey: key)

        var corruptedNonce = encrypted.nonce
        corruptedNonce[corruptedNonce.startIndex] ^= 0xAA

        let tampered = VaultCiphertext(
            ciphertext: encrypted.ciphertext,
            nonce: corruptedNonce,
            associatedData: encrypted.associatedData
        )

        XCTAssertThrowsError(
            try VaultEncryption.decryptEntry(tampered, vaultKey: key)
        ) { error in
            guard case VaultEncryptionError.decryptionFailure = error else {
                XCTFail("Expected decryptionFailure, got \(error)")
                return
            }
        }
    }

    // MARK: - Associated Data Must Match

    func testAssociatedDataMismatchFails() throws {
        let key = try makeVaultKey()
        let plaintext = "with associated data".data(using: .utf8)!

        let ad = "AAD-TEST".data(using: .utf8)!
        let encrypted = try VaultEncryption.encryptEntry(
            plaintext: plaintext,
            vaultKey: key,
            associatedData: ad
        )

        let wrongAD = "DIFFERENT-AAD".data(using: .utf8)!

        let tampered = VaultCiphertext(
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            associatedData: wrongAD
        )

        XCTAssertThrowsError(
            try VaultEncryption.decryptEntry(tampered, vaultKey: key)
        ) { error in
            guard case VaultEncryptionError.decryptionFailure = error else {
                XCTFail("Expected decryptionFailure, got \(error)")
                return
            }
        }
    }

    // MARK: - Nonce Uniqueness

    func testNonceIsUniqueAcrossEncryptions() throws {
        let key = try makeVaultKey()
        let plaintext = "testing nonces".data(using: .utf8)!

        let e1 = try VaultEncryption.encryptEntry(plaintext: plaintext, vaultKey: key)
        let e2 = try VaultEncryption.encryptEntry(plaintext: plaintext, vaultKey: key)

        XCTAssertNotEqual(e1.nonce, e2.nonce, "Nonces must be unique")
    }

    // MARK: - ZeroizedData Safety Test

    func testZeroizedDataCopiesRemainIntact() throws {
        let key = try makeVaultKey()
        let plaintext = "preserve integrity".data(using: .utf8)!

        let encrypted = try VaultEncryption.encryptEntry(plaintext: plaintext, vaultKey: key)
        let decrypted = try VaultEncryption.decryptEntry(encrypted, vaultKey: key)

        let d1 = decrypted.dataValue
        let d2 = decrypted.dataValue

        XCTAssertEqual(d1, d2)
        XCTAssertFalse(d1.allSatisfy({ $0 == 0 }), "Copy must not be wiped prematurely")
    }

    // MARK: - Codable Round Trip

    func testVaultCiphertextCodableRoundTrip() throws {
        let key = try makeVaultKey()
        let plaintext = "serialize me".data(using: .utf8)!

        let encrypted = try VaultEncryption.encryptEntry(plaintext: plaintext, vaultKey: key)

        let encoded = try JSONEncoder().encode(encrypted)
        let decoded = try JSONDecoder().decode(VaultCiphertext.self, from: encoded)

        XCTAssertEqual(encrypted.ciphertext, decoded.ciphertext)
        XCTAssertEqual(encrypted.nonce, decoded.nonce)
        XCTAssertEqual(encrypted.associatedData, decoded.associatedData)
    }
}

// MARK: - Test convenience extensions

private extension ZeroizedData {
    /// Extracts a Data copy for testing only
    var dataValue: Data {
        try! withBytes { Data($0) }
    }
}
