//
//  VaultEncryption.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/5/25.
//

import Foundation
import CryptoKit

public struct VaultCiphertext: Codable, Equatable {
    /// Ciphertext || tag (no nonce)
    public let ciphertext: Data
    /// 12-byte AES-GCM nonce
    public let nonce: Data
    /// Optional associated data (AAD)
    public let associatedData: Data?

    public init(ciphertext: Data, nonce: Data, associatedData: Data? = nil) {
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.associatedData = associatedData
    }
}

public enum VaultEncryptionError: Error, Equatable {
    case invalidInput
    case randomFailure   // currently unused, but kept for future
    case encryptionFailure
    case decryptionFailure
}

public enum VaultEncryption {

    private static let expectedNonceLength = 12
    private static let tagLength = 16

    // MARK: - Encrypt

    public static func encryptEntry(
        plaintext: Data,
        vaultKey: ZeroizedData,
        associatedData: Data? = nil
    ) throws -> VaultCiphertext {

        guard !plaintext.isEmpty else {
            throw VaultEncryptionError.invalidInput
        }

        // Build AES key from ZeroizedData (single copy, zeroized on exit)
        var keyCopy: Data
        do {
            keyCopy = try vaultKey.withBytes { Data($0) }
        } catch {
            throw VaultEncryptionError.invalidInput
        }
        defer { keyCopy.resetBytes(in: 0..<keyCopy.count) }

        let symmetricKey = SymmetricKey(data: keyCopy)

        // Encrypt using CryptoKit AES.GCM
        let sealedBox: AES.GCM.SealedBox
        do {
            if let ad = associatedData {
                sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: AES.GCM.Nonce(), authenticating: ad)
            } else {
                sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: AES.GCM.Nonce())
            }
        } catch {
            throw VaultEncryptionError.encryptionFailure
        }

        // Extract nonce and build ciphertext||tag (no nonce inside)
        let nonceData = Data(sealedBox.nonce)
        guard nonceData.count == expectedNonceLength else {
            throw VaultEncryptionError.encryptionFailure
        }

        let ct = sealedBox.ciphertext
        let tag = sealedBox.tag

        var combined = Data()
        combined.reserveCapacity(ct.count + tag.count)
        combined.append(ct)
        combined.append(tag)

        guard combined.count >= tagLength else {
            throw VaultEncryptionError.encryptionFailure
        }

        return VaultCiphertext(ciphertext: combined, nonce: nonceData, associatedData: associatedData)
    }

    // MARK: - Decrypt

    public static func decryptEntry(
        _ bundle: VaultCiphertext,
        vaultKey: ZeroizedData
    ) throws -> ZeroizedData {

        guard bundle.nonce.count == expectedNonceLength,
              bundle.ciphertext.count >= tagLength else {
            throw VaultEncryptionError.invalidInput
        }

        // Build AES key from ZeroizedData
        var keyCopy: Data
        do {
            keyCopy = try vaultKey.withBytes { Data($0) }
        } catch {
            throw VaultEncryptionError.invalidInput
        }
        defer { keyCopy.resetBytes(in: 0..<keyCopy.count) }

        let symmetricKey = SymmetricKey(data: keyCopy)

        // Rebuild SealedBox from nonce + (ciphertext || tag)
        let nonce: AES.GCM.Nonce
        do {
            nonce = try AES.GCM.Nonce(data: bundle.nonce)
        } catch {
            throw VaultEncryptionError.invalidInput
        }

        let combined = bundle.ciphertext
        let ct = combined.dropLast(tagLength)
        let tag = combined.suffix(tagLength)

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: ct,
                tag: tag
            )
        } catch {
            throw VaultEncryptionError.decryptionFailure
        }

        // Decrypt
        let plaintext: Data
        do {
            if let ad = bundle.associatedData {
                plaintext = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: ad)
            } else {
                plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
            }
        } catch {
            throw VaultEncryptionError.decryptionFailure
        }

        // Wrap in ZeroizedData and wipe the temporary Data
        var mutablePlaintext = plaintext
        let out = ZeroizedData(copying: mutablePlaintext)
        mutablePlaintext.resetBytes(in: 0..<mutablePlaintext.count)

        return out
    }

    // MARK: - Async

    public static func encryptEntryAsync(
        plaintext: Data,
        vaultKey: ZeroizedData,
        associatedData: Data? = nil
    ) async throws -> VaultCiphertext {

        try Task.checkCancellation()

        return try await Task.detached(priority: .userInitiated) {
            try encryptEntry(plaintext: plaintext, vaultKey: vaultKey, associatedData: associatedData)
        }.value
    }

    public static func decryptEntryAsync(
        _ bundle: VaultCiphertext,
        vaultKey: ZeroizedData
    ) async throws -> ZeroizedData {

        try Task.checkCancellation()

        return try await Task.detached(priority: .userInitiated) {
            try decryptEntry(bundle, vaultKey: vaultKey)
        }.value
    }
}
