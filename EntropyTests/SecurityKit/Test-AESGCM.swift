//
//  Test-AESGCM.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

import XCTest
@testable import Entropy

final class AESGCMTests: XCTestCase {

    func testEncryptDecryptRoundTrip() throws {
        let key = try SecureRandom.bytes(count: 32)
        let plaintext = "Hello AES-GCM!".data(using: .utf8)!
        
        let sealed = try AESGCM.encrypt(plaintext: plaintext, using: key)
        XCTAssertEqual(sealed.nonce.count, 12)
        XCTAssertFalse(sealed.ciphertext.isEmpty)

        let decrypted = try AESGCM.decrypt(sealed, using: key)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testDecryptFailsWithCorruptedCiphertext() throws {
        let key = try SecureRandom.bytes(count: 32)
        let plaintext = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
        
        let sealed = try AESGCM.encrypt(plaintext: plaintext, using: key)

        // IMPORTANT: Make a mutable Data copy, not a slice
        var corrupted = Data(sealed.ciphertext)
        XCTAssertFalse(corrupted.isEmpty)

        // Flip first byte
        corrupted[0] ^= 0xFF

        let corruptedBox = AESGCM.SealedBox(ciphertext: corrupted, nonce: sealed.nonce)

        XCTAssertThrowsError(try AESGCM.decrypt(corruptedBox, using: key)) { error in
            XCTAssertEqual(error as? AESGCMError, .authFailed)
        }
    }

    func testDecryptFailsWithWrongKey() throws {
        let key = try SecureRandom.bytes(count: 32)
        let wrongKey = try SecureRandom.bytes(count: 32)
        let plaintext = "Secret message".data(using: .utf8)!
        
        let sealed = try AESGCM.encrypt(plaintext: plaintext, using: key)
        
        XCTAssertThrowsError(try AESGCM.decrypt(sealed, using: wrongKey)) { error in
            XCTAssertEqual(error as? AESGCMError, .authFailed)
        }
    }
}
