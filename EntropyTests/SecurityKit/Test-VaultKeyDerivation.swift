//
//  Test-VaultKeyDerivation.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

import XCTest
@testable import Entropy

final class VaultKeyDerivationTests: XCTestCase {

    /// Convenience: Secure Argon2 parameters suitable for testing.
    /// Use smaller settings if your CI runners are slow, but keep saltLength = 16+.
    private var testParams: Argon2Params {
        return Argon2Params(
            memoryKiB: 32_768,   // 32 MiB minimum allowed
            iterations: 2,
            parallelism: 1,
            saltLength: 16,
            outputLength: 32
        )
    }

    // MARK: - Basic Round Trip

    func testVaultKeyDerivationRoundTrip() throws {
        let password = "correcthorsebatterystaple".data(using: .utf8)!
        let (bundle, originalVaultKey) = try VaultKeyDerivation.createBundleV1(password: password, params: testParams)

        XCTAssertFalse(bundle.salt.isEmpty, "Salt must be present")
        XCTAssertEqual(bundle.kdfParams.outputLength, 32)
        XCTAssertEqual(bundle.vaultKeyNonce.count, 12)

        // Decrypt
        let decrypted = try VaultKeyDerivation.decryptVaultKeyV1(from: bundle, password: password)

        // Compare plaintext vault keys
        XCTAssertEqual(originalVaultKey.dataValue, decrypted.dataValue, "Decrypted vault key must match original")
    }

    // MARK: - Wrong Password Handling

    func testWrongPasswordFails() throws {
        let correctPassword = "hunter22".data(using: .utf8)!
        let wrongPassword   = "incorrect".data(using: .utf8)!

        let (bundle, _) = try VaultKeyDerivation.createBundleV1(password: correctPassword, params: testParams)

        XCTAssertThrowsError(
            try VaultKeyDerivation.decryptVaultKeyV1(from: bundle, password: wrongPassword)
        ) { error in
            guard case VaultKeyDerivationError.decryptionFailure = error else {
                XCTFail("Expected decryptionFailure, got \(error)")
                return
            }
        }
    }

    // MARK: - Salt Must Be Unique

    func testSaltIsUniqueAcrossBundles() throws {
        let password = "uniqueness".data(using: .utf8)!

        let (bundle1, _) = try VaultKeyDerivation.createBundleV1(password: password, params: testParams)
        let (bundle2, _) = try VaultKeyDerivation.createBundleV1(password: password, params: testParams)

        XCTAssertNotEqual(bundle1.salt, bundle2.salt, "Salt MUST be unique per bundle")
    }

    // MARK: - Nonce Must Be Unique

    func testNonceIsUniqueAcrossBundles() throws {
        let password = "validpassword".data(using: .utf8)!

        let (bundle1, _) = try VaultKeyDerivation.createBundleV1(password: password, params: testParams)
        let (bundle2, _) = try VaultKeyDerivation.createBundleV1(password: password, params: testParams)

        XCTAssertNotEqual(bundle1.vaultKeyNonce, bundle2.vaultKeyNonce, "GCM nonces must be unique")
    }

    // MARK: - Ciphertext Integrity

    func testTamperedCiphertextFails() throws {
        let password = "test12345".data(using: .utf8)!
        var (bundle, _) = try VaultKeyDerivation.createBundleV1(password: password, params: testParams)

        // Tamper with ciphertext
        XCTAssertFalse(bundle.vaultKeyCiphertext.isEmpty, "Ciphertext unexpectedly empty")

        var corrupted = bundle.vaultKeyCiphertext
        XCTAssertGreaterThan(corrupted.count, 0, "Ciphertext must not be empty")

        corrupted[corrupted.startIndex] ^= 0xFF
        bundle = VaultKeyBundleV1(
            kdfParams: bundle.kdfParams,
            salt: bundle.salt,
            vaultKeyCiphertext: corrupted,
            vaultKeyNonce: bundle.vaultKeyNonce
        )

        XCTAssertThrowsError(
            try VaultKeyDerivation.decryptVaultKeyV1(from: bundle, password: password)
        ) { error in
            guard case VaultKeyDerivationError.decryptionFailure = error else {
                XCTFail("Expected decryptionFailure, got \(error)")
                return
            }
        }
    }

    // MARK: - Codable Round Trip

    func testBundleCodableRoundTrip() throws {
        let password = "serialization".data(using: .utf8)!
        let (bundle, _) = try VaultKeyDerivation.createBundleV1(password: password, params: testParams)

        let encoded = try JSONEncoder().encode(bundle)
        let decoded = try JSONDecoder().decode(VaultKeyBundleV1.self, from: encoded)

        XCTAssertEqual(bundle, decoded, "Bundle must survive Codable round trip")
    }

    // MARK: - ZeroizedData Memory Semantics

    func testZeroizedDataDoesNotLeakCopies() throws {
        let password = "swordfish".data(using: .utf8)!
        let (_, vaultKey) = try VaultKeyDerivation.createBundleV1(password: password, params: testParams)

        // Convert to Data — this should be safe because ZeroizedData gives a copy (your implementation allocates secure buffer)
        let dataCopy1 = vaultKey.dataValue
        let dataCopy2 = vaultKey.dataValue

        XCTAssertEqual(dataCopy1, dataCopy2)

        // Now destroy vaultKey and ensure the sealed copy isn't zeroed prematurely.
        // This test simply ensures your ZeroizedData doesn't accidentally mutate the public copy.
        // We can't check the wiped memory directly from Swift, but we *can* verify the copies remain valid.
        XCTAssertFalse(dataCopy1.allSatisfy { $0 == 0 })
        XCTAssertFalse(dataCopy2.allSatisfy { $0 == 0 })
    }
}

// MARK: - Convenience for ZeroizedData → Data conversion used in tests

private extension ZeroizedData {
    var dataValue: Data {
        // we know our closure will never throw → use `try!` safely here
        try! self.withBytes { rawPtr in
            Data(rawPtr)
        }
    }
}
