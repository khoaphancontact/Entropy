//
//  Test-EncryptedPayload.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  EncryptedPayloadTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class EncryptedPayloadTests: XCTestCase {

    // MARK: - Helpers

    private func makeKey() throws -> ZeroizedData {
        let raw = try SecureRandom.bytes(count: 32)
        return ZeroizedData(copying: raw)
    }

    private func makePlaintext(_ s: String) -> Data {
        s.data(using: .utf8)!
    }

    // MARK: - Round Trip

    func testEncryptedPayloadRoundTrip() throws {
        let key = try makeKey()
        let plaintext = makePlaintext("super secret autofill payload")
        let aad = "test-AAD".data(using: .utf8)!

        let encrypted = try EncryptedPayload.encrypt(
            plaintext: plaintext,
            key: key,
            purpose: .autofillEntry,
            userAssociatedData: aad,
            version: 1
        )

        let decrypted = try encrypted.decrypt(using: key)
        XCTAssertEqual(decrypted.dataValue, plaintext)
    }

    // MARK: - Wrong Key Must Fail

    func testDecryptFailsWithWrongKey() throws {
        let key1 = try makeKey()
        let key2 = try makeKey()
        let plaintext = makePlaintext("data")

        let enc = try EncryptedPayload.encrypt(
            plaintext: plaintext,
            key: key1,
            purpose: .autofillEntry
        )

        XCTAssertThrowsError(
            try enc.decrypt(using: key2)
        ) { error in
            guard case EncryptedPayloadError.decryptionFailed = error else {
                XCTFail("Expected .decryptionFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Purpose Binding

    func testDecryptFailsWhenPurposeChanged() throws {
        let key = try makeKey()
        let plaintext = makePlaintext("data")

        let enc = try EncryptedPayload.encrypt(
            plaintext: plaintext,
            key: key,
            purpose: .autofillEntry
        )

        // Create a modified payload with purpose changed — AAD mismatch.
        let tampered = EncryptedPayload(
            version: enc.version,
            purpose: .fastUnlockKey,    // changed purpose
            ciphertext: enc.ciphertext,
            nonce: enc.nonce,
            userAssociatedData: enc.userAssociatedData
        )

        XCTAssertThrowsError(
            try tampered.decrypt(using: key)
        ) { error in
            guard case EncryptedPayloadError.decryptionFailed = error else {
                XCTFail("Expected .decryptionFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - User AAD Binding

    func testDecryptFailsWhenUserAADChanged() throws {
        let key = try makeKey()
        let plaintext = makePlaintext("otp secret")

        let aad1 = "aaa".data(using: .utf8)!
        let aad2 = "bbb".data(using: .utf8)!  // different

        let enc = try EncryptedPayload.encrypt(
            plaintext: plaintext,
            key: key,
            purpose: .autofillEntry,
            userAssociatedData: aad1
        )

        let tampered = EncryptedPayload(
            version: enc.version,
            purpose: enc.purpose,
            ciphertext: enc.ciphertext,
            nonce: enc.nonce,
            userAssociatedData: aad2   // wrong AAD
        )

        XCTAssertThrowsError(
            try tampered.decrypt(using: key)
        ) { error in
            guard case EncryptedPayloadError.decryptionFailed = error else {
                XCTFail("Expected .decryptionFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Version Binding

    func testDecryptFailsWhenVersionChanged() throws {
        let key = try makeKey()
        let plaintext = makePlaintext("payload")

        let enc = try EncryptedPayload.encrypt(
            plaintext: plaintext,
            key: key,
            purpose: .autofillEntry,
            version: 1
        )

        // Change version → AAD mismatch.
        let tampered = EncryptedPayload(
            version: 2,  // changed
            purpose: enc.purpose,
            ciphertext: enc.ciphertext,
            nonce: enc.nonce,
            userAssociatedData: enc.userAssociatedData
        )

        XCTAssertThrowsError(
            try tampered.decrypt(using: key)
        ) { error in
            guard case EncryptedPayloadError.decryptionFailed = error else {
                XCTFail("Expected .decryptionFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Tampered Ciphertext

    func testTamperedCiphertextFails() throws {
        let key = try makeKey()
        let plaintext = makePlaintext("hello")

        let enc = try EncryptedPayload.encrypt(
            plaintext: plaintext,
            key: key,
            purpose: .generic,
            version: 1
        )

        var corrupted = enc.ciphertext
        corrupted[corrupted.startIndex] ^= 0xFF

        let tampered = EncryptedPayload(
            version: enc.version,
            purpose: enc.purpose,
            ciphertext: corrupted,
            nonce: enc.nonce,
            userAssociatedData: enc.userAssociatedData
        )

        XCTAssertThrowsError(
            try tampered.decrypt(using: key)
        ) { error in
            guard case EncryptedPayloadError.decryptionFailed = error else {
                XCTFail("Expected .decryptionFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Tampered Nonce

    func testTamperedNonceFails() throws {
        let key = try makeKey()
        let plaintext = makePlaintext("nonce test")

        let enc = try EncryptedPayload.encrypt(
            plaintext: plaintext,
            key: key,
            purpose: .generic
        )

        var badNonce = enc.nonce
        badNonce[badNonce.startIndex] ^= 0xAA

        let tampered = EncryptedPayload(
            version: enc.version,
            purpose: enc.purpose,
            ciphertext: enc.ciphertext,
            nonce: badNonce,
            userAssociatedData: enc.userAssociatedData
        )

        XCTAssertThrowsError(
            try tampered.decrypt(using: key)
        ) { error in
            guard case EncryptedPayloadError.decryptionFailed = error else {
                XCTFail("Expected .decryptionFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Codable Round Trip

    func testCodableRoundTrip() throws {
        let key = try makeKey()
        let plaintext = makePlaintext("serialize me")

        let enc = try EncryptedPayload.encrypt(
            plaintext: plaintext,
            key: key,
            purpose: .generic
        )

        let encoded = try JSONEncoder().encode(enc)
        let decoded = try JSONDecoder().decode(EncryptedPayload.self, from: encoded)

        XCTAssertEqual(enc, decoded)
    }

    // MARK: - Validation-level invalid payload

    func testInvalidPayloadFailsEarly() throws {
        let key = try makeKey()

        // nonce too short → validateVaultCiphertext should reject
        let bad = EncryptedPayload(
            version: 1,
            purpose: .generic,
            ciphertext: Data(repeating: 0x01, count: 32),
            nonce: Data(repeating: 0x02, count: 4), // invalid
            userAssociatedData: nil
        )

        XCTAssertThrowsError(
            try bad.decrypt(using: key)
        ) { error in
            guard case EncryptedPayloadError.invalidPayload = error else {
                XCTFail("Expected .invalidPayload")
                return
            }
        }
    }
}

// MARK: - ZeroizedData test helper

private extension ZeroizedData {
    /// Extracts a Data copy from secure buffer for testing only.
    var dataValue: Data {
        try! withBytes { Data($0) }
    }
}
