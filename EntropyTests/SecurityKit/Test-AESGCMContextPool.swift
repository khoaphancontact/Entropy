//
//  Untitled.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  AESGCMContextPoolTests.swift
//  EntropyTests
//
//  Created by ChatGPT on 12/6/25.
//

import XCTest
@testable import Entropy

final class AESGCMContextPoolTests: XCTestCase {

    func testRoundTripDecryption() async throws {
        let pool = AESGCMContextPool()

        let keyData = try SecureRandom.bytes(count: 32)
        let key = ZeroizedData(copying: keyData)

        let plaintext = "Hello Context Pool".data(using: .utf8)!
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: plaintext,
            vaultKey: key
        )

        let decrypted = try await pool.decryptAsync(bundle, vaultKey: key)

        decrypted.withBytes { raw in
            let str = String(data: Data(raw), encoding: .utf8)
            XCTAssertEqual(str, "Hello Context Pool")
        }
    }

    func testTamperedCiphertextFails() async throws {
        let pool = AESGCMContextPool()

        let keyData = try SecureRandom.bytes(count: 32)
        let key = ZeroizedData(copying: keyData)

        let plaintext = Data("Secret".utf8)
        var bundle = try VaultEncryption.encryptEntry(
            plaintext: plaintext,
            vaultKey: key
        )

        // tamper
        var corrupted = bundle.ciphertext
        corrupted[0] ^= 0xFF
        bundle = VaultCiphertext(
            ciphertext: corrupted,
            nonce: bundle.nonce,
            associatedData: bundle.associatedData
        )

        await XCTAssertThrowsErrorAsync({
            _ = try await pool.decryptAsync(bundle, vaultKey: key)
        }) { error in
            XCTAssertEqual(error as? VaultEncryptionError, .decryptionFailure)
        }
    }

    func testPoolIsActorIsolated() async throws {
        let pool = AESGCMContextPool()
        let keyData = try SecureRandom.bytes(count: 32)
        let key = ZeroizedData(copying: keyData)

        let plaintext = Data("Isolation".utf8)
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: plaintext,
            vaultKey: key
        )

        // concurrently call decrypt from multiple tasks
        async let a = pool.decryptAsync(bundle, vaultKey: key)
        async let b = pool.decryptAsync(bundle, vaultKey: key)
        async let c = pool.decryptAsync(bundle, vaultKey: key)

        let outA = try await a
        let outB = try await b
        let outC = try await c

        try outA.withBytes { A in
            try outB.withBytes { B in
                try outC.withBytes { C in
                    XCTAssertEqual(Data(A), Data(B))
                    XCTAssertEqual(Data(B), Data(C))
                }
            }
        }
    }
}
