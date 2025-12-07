//
//  AESGCM.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/5/25.
//

import Foundation
import CryptoKit

public enum AESGCMError: Error {
    case invalidKeyLength
    case invalidNonceLength
    case malformedCiphertext
    case authFailed
}

public enum AESGCM {
    public struct SealedBox: Sendable {
        public let ciphertext: Data   // ciphertext || tag (concatenated)
        public let nonce: Data        // 12 bytes
        public init(ciphertext: Data, nonce: Data) {
            self.ciphertext = ciphertext
            self.nonce = nonce
        }
    }

    // Encrypts plaintext with a 32-byte key. Generates a 12-byte random nonce.
    // Returns ciphertext concatenated with the 16-byte GCM tag and the nonce separately.
    public static func encrypt(plaintext: Data, using key: Data) throws -> SealedBox {
        guard key.count == 32 else { throw AESGCMError.invalidKeyLength }
        let nonceBytes = try SecureRandom.bytes(count: 12)
        let symmetricKey = SymmetricKey(data: key)
        let sealed = try CryptoKit.AES.GCM.seal(plaintext, using: symmetricKey, nonce: .init(data: nonceBytes))
        // CryptoKit provides ciphertext and tag separately; concatenate for transport/storage.
        let combined = sealed.ciphertext + sealed.tag
        return SealedBox(ciphertext: combined, nonce: nonceBytes)
    }

    // Decrypts a sealed box with a 32-byte key. Expects ciphertext||tag combined.
    public static func decrypt(_ box: SealedBox, using key: Data) throws -> Data {
        guard key.count == 32 else { throw AESGCMError.invalidKeyLength }
        guard box.nonce.count == 12 else { throw AESGCMError.invalidNonceLength }
        // GCM tag is 16 bytes; ensure we have at least that many bytes.
        guard box.ciphertext.count >= 16 else { throw AESGCMError.malformedCiphertext }
        let ct = box.ciphertext.dropLast(16)
        let tag = box.ciphertext.suffix(16)
        let symmetricKey = SymmetricKey(data: key)
        let sealed = try CryptoKit.AES.GCM.SealedBox(
            nonce: .init(data: box.nonce),
            ciphertext: Data(ct),
            tag: Data(tag)
        )
        do {
            return try CryptoKit.AES.GCM.open(sealed, using: symmetricKey)
        } catch {
            throw AESGCMError.authFailed
        }
    }
}
