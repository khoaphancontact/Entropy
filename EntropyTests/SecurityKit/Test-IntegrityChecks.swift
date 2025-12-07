//
//  Test-IntegrityChecks.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  IntegrityChecksTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy   // or your module name

final class IntegrityChecksTests: XCTestCase {

    // MARK: - Helpers

    /// Produce valid Argon2Params for testing.
    private var validParams: Argon2Params {
        Argon2Params(
            memoryKiB: 32_768,
            iterations: 2,
            parallelism: 1,
            saltLength: 16,
            outputLength: 32
        )
    }

    /// A helper to generate a secure random ZeroizedData key.
    private func makeKey() throws -> ZeroizedData {
        let raw = try SecureRandom.bytes(count: 32)
        return ZeroizedData(copying: raw)
    }

    // MARK: - Argon2 Parameter Validation

    func testArgon2ParamsValidationSucceeds() throws {
        XCTAssertNoThrow(try IntegrityChecks.validateArgon2Params(validParams))
    }

    func testArgon2ParamsValidationFailsOnBadMemory() throws {
        let bad = Argon2Params(
            memoryKiB: 1024, // too low
            iterations: 2,
            parallelism: 1,
            saltLength: 16,
            outputLength: 32
        )
        XCTAssertThrowsError(try IntegrityChecks.validateArgon2Params(bad))
    }

    func testArgon2ParamsValidationFailsOnBadSaltLength() throws {
        let bad = Argon2Params(
            memoryKiB: 32_768,
            iterations: 2,
            parallelism: 1,
            saltLength: 8, // must be >=16
            outputLength: 32
        )
        XCTAssertThrowsError(try IntegrityChecks.validateArgon2Params(bad))
    }

    // MARK: - VaultKeyBundle Validation

    func testValidVaultKeyBundlePassesValidation() throws {
        let params = validParams
        let salt = try SecureRandom.bytes(count: params.saltLength)

        // Minimal valid ciphertext and nonce for AES-GCM
        let ciphertext = Data(repeating: 0xAA, count: 32) // >= 16 bytes
        let nonce = Data(repeating: 0xBB, count: 12)

        let bundle = VaultKeyBundleV1(
            kdfParams: params,
            salt: salt,
            vaultKeyCiphertext: ciphertext,
            vaultKeyNonce: nonce
        )

        XCTAssertNoThrow(try IntegrityChecks.validateVaultKeyBundle(bundle))
    }

    func testVaultKeyBundleFailsWithWrongSaltLength() throws {
        let params = validParams
        let salt = try SecureRandom.bytes(count: 8) // invalid

        let bundle = VaultKeyBundleV1(
            kdfParams: params,
            salt: salt,
            vaultKeyCiphertext: Data(repeating: 0xCC, count: 32),
            vaultKeyNonce: Data(repeating: 0xDD, count: 12)
        )

        XCTAssertThrowsError(try IntegrityChecks.validateVaultKeyBundle(bundle))
    }

    func testVaultKeyBundleFailsWithShortCiphertext() throws {
        let params = validParams
        let salt = try SecureRandom.bytes(count: params.saltLength)

        let bundle = VaultKeyBundleV1(
            kdfParams: params,
            salt: salt,
            vaultKeyCiphertext: Data(repeating: 0xEE, count: 8), // < 16
            vaultKeyNonce: Data(repeating: 0xDD, count: 12)
        )

        XCTAssertThrowsError(try IntegrityChecks.validateVaultKeyBundle(bundle))
    }

    // MARK: - VaultCiphertext Validation

    func testValidVaultCiphertextPasses() throws {
        let ct = Data(repeating: 0xAA, count: 32)
        let nonce = Data(repeating: 0xBB, count: 12)

        let vct = VaultCiphertext(ciphertext: ct, nonce: nonce)

        XCTAssertNoThrow(try IntegrityChecks.validateVaultCiphertext(vct))
    }

    func testInvalidNonceFailsCiphertextValidation() throws {
        let ct = Data(repeating: 0xAA, count: 32)
        let nonce = Data(repeating: 0xBB, count: 8) // too short

        let vct = VaultCiphertext(ciphertext: ct, nonce: nonce)

        XCTAssertThrowsError(try IntegrityChecks.validateVaultCiphertext(vct))
    }

    func testShortCiphertextFailsCiphertextValidation() throws {
        let ct = Data(repeating: 0xAA, count: 8) // too short
        let nonce = Data(repeating: 0xBB, count: 12)

        let vct = VaultCiphertext(ciphertext: ct, nonce: nonce)

        XCTAssertThrowsError(try IntegrityChecks.validateVaultCiphertext(vct))
    }

    // MARK: - SHA-256

    func testSHA256Deterministic() {
        let input = "test123".data(using: .utf8)!
        let h1 = IntegrityChecks.sha256(input)
        let h2 = IntegrityChecks.sha256(input)
        XCTAssertEqual(h1, h2)
    }

    func testSHA256VerifySuccess() {
        let input = "hello world".data(using: .utf8)!
        let hash = IntegrityChecks.sha256(input)
        XCTAssertTrue(IntegrityChecks.verifySHA256(data: input, expectedHash: hash))
    }

    func testSHA256VerifyFail() {
        let input = "hello world".data(using: .utf8)!
        let wrong = Data(repeating: 0x00, count: 32)
        XCTAssertFalse(IntegrityChecks.verifySHA256(data: input, expectedHash: wrong))
    }

    // MARK: - HMAC

    func testHMACComputesCorrectly() throws {
        let key = try makeKey()
        let message = "hello mac".data(using: .utf8)!

        let mac1 = try IntegrityChecks.hmacSHA256(key: key, data: message)
        let mac2 = try IntegrityChecks.hmacSHA256(key: key, data: message)

        XCTAssertEqual(mac1, mac2)
    }

    func testHMACVerifySuccess() throws {
        let key = try makeKey()
        let msg = "aaabbbccc".data(using: .utf8)!
        let mac = try IntegrityChecks.hmacSHA256(key: key, data: msg)

        XCTAssertTrue(try IntegrityChecks.verifyHMACSHA256(key: key, data: msg, expectedMAC: mac))
    }

    func testHMACVerifyFailWithWrongMAC() throws {
        let key = try makeKey()
        let msg = "important data".data(using: .utf8)!
        let mac = try IntegrityChecks.hmacSHA256(key: key, data: msg)

        // Tamper one byte
        var wrong = mac
        wrong[0] ^= 0xFF

        XCTAssertFalse(try IntegrityChecks.verifyHMACSHA256(key: key, data: msg, expectedMAC: wrong))
    }

    func testHMACVerifyFailWithWrongData() throws {
        let key = try makeKey()
        let msg = "data1".data(using: .utf8)!
        let mac = try IntegrityChecks.hmacSHA256(key: key, data: msg)

        let differentMsg = "data2".data(using: .utf8)!

        XCTAssertFalse(try IntegrityChecks.verifyHMACSHA256(key: key, data: differentMsg, expectedMAC: mac))
    }

    // MARK: - Vault Blob Hash (high-level)

    func testVaultBlobHashRoundTrip() {
        let blob = "vault bytes here".data(using: .utf8)!
        let hash = IntegrityChecks.computeVaultBlobHash(blob)

        XCTAssertTrue(IntegrityChecks.verifyVaultBlobHash(blob, expectedHash: hash))
    }

    func testVaultBlobHashFail() {
        let blob = "vault bytes here".data(using: .utf8)!
        let hash = IntegrityChecks.computeVaultBlobHash(blob)

        let modified = "vault bytes HERE".data(using: .utf8)! // changed
        XCTAssertFalse(IntegrityChecks.verifyVaultBlobHash(modified, expectedHash: hash))
    }
}

// MARK: - ZeroizedData Test Helper

private extension ZeroizedData {
    /// Extract a Data copy for comparisons — test-only.
    var dataValue: Data {
        try! withBytes { Data($0) }
    }
}
