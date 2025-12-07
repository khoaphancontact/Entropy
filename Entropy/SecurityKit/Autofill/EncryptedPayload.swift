//
//  EncryptedPayload.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  EncryptedPayload.swift
//  Entropy
//
//  Versioned encrypted payload for app <-> extension communication.
//  Wraps AES-GCM VaultEncryption with explicit purpose + version binding via AEAD.
//
import Foundation

/// High-level encrypted payload used to transport sensitive data
/// (e.g. Autofill entries, fast-unlock tokens) between processes/components.
///
/// This is the *only* thing that should move between the main app and extensions.
/// Plaintext types like `AutofillEntry` must never be serialized directly.
public struct EncryptedPayload: Codable, Equatable, Sendable {

    /// Logical purpose of this payload. This is bound into AEAD associated data.
    public enum Purpose: String, Codable, Sendable {
        /// Carries a decrypted vault entry (username/password/etc.) for Autofill.
        case autofillEntry = "autofill_entry"
        /// Carries a fast-unlock-related token or key material.
        case fastUnlockKey = "fast_unlock_key"
        /// Generic encrypted blob.
        case generic = "generic"
    }

    /// Payload format version (for future migrations).
    public let version: UInt8

    /// Logical purpose of the payload (bound into AEAD AAD).
    public let purpose: Purpose

    /// AES-GCM ciphertext || tag (no nonce).
    public let ciphertext: Data

    /// AES-GCM nonce (12 bytes).
    public let nonce: Data

    /// Optional user-level associated data *not* secret.
    /// This is folded into the internal AEAD AAD alongside version + purpose.
    public let userAssociatedData: Data?

    public init(
        version: UInt8 = 1,
        purpose: Purpose,
        ciphertext: Data,
        nonce: Data,
        userAssociatedData: Data? = nil
    ) {
        self.version = version
        self.purpose = purpose
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.userAssociatedData = userAssociatedData
    }
}

// MARK: - Errors

public enum EncryptedPayloadError: Error, Equatable {
    case invalidPayload
    case encryptionFailed
    case decryptionFailed
}

// MARK: - Crypto helpers

public extension EncryptedPayload {

    /// Encrypts arbitrary plaintext into an `EncryptedPayload` using the given symmetric key.
    ///
    /// - Parameters:
    ///   - plaintext: Raw plaintext bytes to encrypt.
    ///   - key: Vault key (or other symmetric key) as `ZeroizedData`.
    ///   - purpose: Logical purpose of this payload (bound into AEAD AAD).
    ///   - userAssociatedData: Optional non-secret associated data to bind into AEAD.
    ///   - version: Payload version, defaults to 1.
    ///
    /// - Returns: A fully-populated `EncryptedPayload`.
    /// - Throws: `EncryptedPayloadError.encryptionFailed` on failure.
    static func encrypt(
        plaintext: Data,
        key: ZeroizedData,
        purpose: Purpose,
        userAssociatedData: Data? = nil,
        version: UInt8 = 1
    ) throws -> EncryptedPayload {
        // Build AEAD associated data from version + purpose + user AAD.
        let aad = buildAAD(version: version, purpose: purpose, userAAD: userAssociatedData)

        // Reuse VaultEncryption to do the actual AES-GCM work.
        let vaultCiphertext: VaultCiphertext
        do {
            vaultCiphertext = try VaultEncryption.encryptEntry(
                plaintext: plaintext,
                vaultKey: key,
                associatedData: aad
            )
        } catch {
            throw EncryptedPayloadError.encryptionFailed
        }

        return EncryptedPayload(
            version: version,
            purpose: purpose,
            ciphertext: vaultCiphertext.ciphertext,
            nonce: vaultCiphertext.nonce,
            userAssociatedData: userAssociatedData
        )
    }

    /// Decrypts this payload using the provided symmetric key.
    ///
    /// - Parameter key: The symmetric key as `ZeroizedData`.
    /// - Returns: The decrypted plaintext wrapped in `ZeroizedData`.
    /// - Throws: `EncryptedPayloadError.invalidPayload` or `.decryptionFailed`.
    func decrypt(using key: ZeroizedData) throws -> ZeroizedData {
        // Rebuild AEAD associated data exactly as in encrypt().
        let aad = EncryptedPayload.buildAAD(
            version: version,
            purpose: purpose,
            userAAD: userAssociatedData
        )

        // Construct a VaultCiphertext from stored fields.
        let bundle = VaultCiphertext(
            ciphertext: ciphertext,
            nonce: nonce,
            associatedData: aad
        )

        // Structural validation before doing any crypto.
        do {
            _ = try IntegrityChecks.validateVaultCiphertext(bundle)
        } catch {
            throw EncryptedPayloadError.invalidPayload
        }

        // Decrypt via VaultEncryption.
        do {
            return try VaultEncryption.decryptEntry(bundle, vaultKey: key)
        } catch {
            throw EncryptedPayloadError.decryptionFailed
        }
    }
}

// MARK: - Internal AAD construction

private extension EncryptedPayload {

    /// Builds AEAD associated data binding version, purpose, and optional user AAD.
    ///
    /// Layout (not secret, but stable):
    /// [ version (1 byte) ]
    /// [ purposeLength (1 byte) ][ purpose UTF-8 bytes ]
    /// [ userAADLength (4 bytes, big-endian) ][ userAAD bytes... ]
    static func buildAAD(
        version: UInt8,
        purpose: Purpose,
        userAAD: Data?
    ) -> Data {
        var out = Data()
        out.append(version)

        // Purpose as UTF-8
        let purposeBytes = purpose.rawValue.data(using: .utf8) ?? Data()
        let purposeLen = UInt8(clamping: purposeBytes.count)
        out.append(purposeLen)
        out.append(purposeBytes.prefix(Int(purposeLen)))

        // User AAD length (UInt32 big-endian) + bytes
        if let aad = userAAD {
            var len = UInt32(aad.count).bigEndian
            withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
            out.append(aad)
        } else {
            var zero: UInt32 = 0
            zero = zero.bigEndian
            withUnsafeBytes(of: &zero) { out.append(contentsOf: $0) }
        }

        return out
    }
}
