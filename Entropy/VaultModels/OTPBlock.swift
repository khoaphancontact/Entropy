//
//  OTPBlock.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  OTPBlock.swift
//  EntropyVaultModels
//

import Foundation

// MARK: - Supported Algorithms

public enum OTPAlgorithm: String, Codable, Sendable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"
}

// MARK: - OTPBlock Errors

public enum OTPBlockError: Error, Equatable {
    case invalidAlgorithm
    case invalidDigits
    case invalidPeriod
    case invalidCiphertext
    case missingCiphertext
    case metadataDecodeFailed
}

// MARK: - OTP Metadata (Encrypted)

/// Optional encrypted metadata for OTP, similar to VaultEntryMetadata.
/// Allows tracking last-used timestamp or other analytics.
public struct OTPMetadata: Codable, Equatable, Sendable {
    public let lastUsed: Date?

    public init(lastUsed: Date? = nil) {
        self.lastUsed = lastUsed
    }
}

// MARK: - OTPBlock

/// Encrypted OTP configuration block stored by UUID.
/// This is referenced by VaultEntry.otpBlockID.
public struct OTPBlock: Codable, Equatable, Identifiable, Sendable {

    // MARK: - Identity

    public let id: UUID

    // MARK: - Configuration

    public let algorithm: OTPAlgorithm
    public let digits: Int
    public let period: Int

    /// AES-GCM encrypted Base32 secret.
    public let encryptedSecret: EncryptedField

    /// Optional encrypted OTP metadata.
    public let encryptedMetadata: EncryptedField?

    // MARK: - Init

    public init(
        id: UUID = UUID(),
        algorithm: OTPAlgorithm,
        digits: Int,
        period: Int,
        encryptedSecret: EncryptedField,
        encryptedMetadata: EncryptedField? = nil
    ) {
        self.id = id
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.encryptedSecret = encryptedSecret
        self.encryptedMetadata = encryptedMetadata
    }
}

// MARK: - Validation

public extension OTPBlock {

    func validate() throws {
        switch algorithm {
        case .sha1, .sha256, .sha512:
            break
        }

        guard digits >= 4 && digits <= 10 else {
            throw OTPBlockError.invalidDigits
        }

        guard period >= 5 && period <= 300 else {
            throw OTPBlockError.invalidPeriod
        }

        do {
            try encryptedSecret.validate()
            try encryptedMetadata?.validate()
        } catch {
            throw OTPBlockError.invalidCiphertext
        }
    }
}

// MARK: - Partial Decrypt

public extension OTPBlock {

    /// Decrypt only the secret for TOTP generation.
    func decryptSecret(vaultKey: ZeroizedData) throws -> ZeroizedData {
        return try VaultEncryption.decryptEntry(encryptedSecret.bundle, vaultKey: vaultKey)
    }

    /// Decrypt OTP metadata (e.g. lastUsed), if present.
    func decryptMetadata(
        vaultKey: ZeroizedData,
        decoder: JSONDecoder = JSONDecoder()
    ) throws -> OTPMetadata? {

        guard let encryptedMetadata = encryptedMetadata else { return nil }

        // Decrypt AES-GCM
        let blob: ZeroizedData
        do {
            blob = try VaultEncryption.decryptEntry(encryptedMetadata.bundle, vaultKey: vaultKey)
        } catch {
            throw OTPBlockError.metadataDecodeFailed
        }

        // Convert ZeroizedData → Data
        let data: Data
        do {
            data = try blob.withBytes { Data($0) }
        } catch {
            throw OTPBlockError.metadataDecodeFailed
        }

        // Decode JSON
        do {
            return try decoder.decode(OTPMetadata.self, from: data)
        } catch {
            throw OTPBlockError.metadataDecodeFailed
        }
    }
}

// MARK: - Encryption Helper for Metadata

public extension OTPMetadata {

    static func encrypt(
        _ metadata: OTPMetadata,
        vaultKey: ZeroizedData,
        now: Date = Date(),
        encoder: JSONEncoder = JSONEncoder()
    ) throws -> EncryptedField {

        let payload = try encoder.encode(metadata)
        let bundle = try VaultEncryption.encryptEntry(plaintext: payload, vaultKey: vaultKey)
        return EncryptedField(bundle: bundle, createdAt: now, updatedAt: now)
    }
}
