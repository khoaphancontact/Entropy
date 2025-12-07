//
//  VaultEntry.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  VaultEntry.swift
//  EntropyVaultModels
//

import Foundation

// MARK: - Codable

extension VaultEntry {

    enum CodingKeys: String, CodingKey {
        case id
        case title
        case domain
        case createdAt
        case updatedAt
        case encryptedUsername
        case encryptedPassword
        case encryptedNotes
        case otpBlockID
        case encryptedMetadata
        case securityInfo
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)

        self.id = try c.decode(UUID.self, forKey: .id)
        self.title = try c.decode(String.self, forKey: .title)
        self.domain = try c.decodeIfPresent(String.self, forKey: .domain)
        self.createdAt = try c.decode(Date.self, forKey: .createdAt)
        self.updatedAt = try c.decode(Date.self, forKey: .updatedAt)

        self.encryptedUsername = try c.decode(EncryptedField.self, forKey: .encryptedUsername)
        self.encryptedPassword = try c.decode(EncryptedField.self, forKey: .encryptedPassword)

        self.encryptedNotes = try c.decodeIfPresent(EncryptedField.self, forKey: .encryptedNotes)
        self.otpBlockID = try c.decodeIfPresent(UUID.self, forKey: .otpBlockID)
        self.encryptedMetadata = try c.decodeIfPresent(EncryptedField.self, forKey: .encryptedMetadata)

        self.securityInfo = try c.decodeIfPresent(VaultEntrySecurityInfo.self, forKey: .securityInfo)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)

        try c.encode(id, forKey: .id)
        try c.encode(title, forKey: .title)
        try c.encodeIfPresent(domain, forKey: .domain)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encode(updatedAt, forKey: .updatedAt)

        try c.encode(encryptedUsername, forKey: .encryptedUsername)
        try c.encode(encryptedPassword, forKey: .encryptedPassword)

        try c.encodeIfPresent(encryptedNotes, forKey: .encryptedNotes)
        try c.encodeIfPresent(otpBlockID, forKey: .otpBlockID)
        try c.encodeIfPresent(encryptedMetadata, forKey: .encryptedMetadata)

        try c.encodeIfPresent(securityInfo, forKey: .securityInfo)
    }
}


// MARK: - Errors

public enum VaultEntryError: Error, Equatable {
    case invalidCiphertext
    case missingCiphertext
    case metadataDecodeFailed
}

// MARK: - EncryptedField

/// Wrapper for a single encrypted field within a VaultEntry.
///
/// Contains:
/// - VaultCiphertext (AES-GCM bundle)
/// - createdAt / updatedAt for that field
public struct EncryptedField: Codable, Equatable, Sendable {
    public let bundle: VaultCiphertext
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        bundle: VaultCiphertext,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.bundle = bundle
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    /// Structural validation via IntegrityChecks.
    public func validate() throws {
        _ = try IntegrityChecks.validateVaultCiphertext(bundle)
    }
}

// MARK: - VaultEntry

/// Encrypted on-disk model for a single vault item.
///
/// All sensitive fields (username, password, notes, OTP secret, metadata)
/// are represented by VaultCiphertext via EncryptedField.
public struct VaultEntry: Codable, Equatable, Identifiable, Sendable {

    // MARK: - Identity & Basic Metadata

    public let id: UUID
    public let title: String
    public let domain: String?

    /// Overall entry timestamps (separate from per-field timestamps).
    public let createdAt: Date
    public let updatedAt: Date

    // MARK: - Encrypted Fields

    public let encryptedUsername: EncryptedField
    public let encryptedPassword: EncryptedField
    public let encryptedNotes: EncryptedField?
    public let otpBlockID: UUID?
    public let encryptedMetadata: EncryptedField?

    /// Optional security info (score / strength).
    /// Implemented in Milestone H.
    public let securityInfo: VaultEntrySecurityInfo?

    // MARK: - Init

    public init(
        id: UUID = UUID(),
        title: String,
        domain: String?,
        createdAt: Date,
        updatedAt: Date,
        encryptedUsername: EncryptedField,
        encryptedPassword: EncryptedField,
        encryptedNotes: EncryptedField? = nil,
        otpBlockID: UUID? = nil,
        encryptedMetadata: EncryptedField? = nil,
        securityInfo: VaultEntrySecurityInfo? = nil
    ) {
        self.id = id
        self.title = title
        self.domain = domain
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.encryptedUsername = encryptedUsername
        self.encryptedPassword = encryptedPassword
        self.encryptedNotes = encryptedNotes
        self.otpBlockID = otpBlockID
        self.encryptedMetadata = encryptedMetadata
        self.securityInfo = securityInfo
    }
}

// MARK: - Validation

public extension VaultEntry {

    /// Validate the structural integrity of all encrypted fields.
    ///
    /// - Throws: VaultEntryError.invalidCiphertext if any field fails validation.
    func validate() throws {
        do {
            try encryptedUsername.validate()
            try encryptedPassword.validate()
            try encryptedNotes?.validate()
            try encryptedMetadata?.validate()
            // Note: OTP secret lives in OTPBlock; validated separately.
        } catch {
            throw VaultEntryError.invalidCiphertext
        }
    }
}

// MARK: - Partial Decrypt Helpers

public extension VaultEntry {

    /// Partially decrypt a specific field using the provided vault key.
    ///
    /// - Parameters:
    ///   - field: Which field to decrypt.
    ///   - vaultKey: Vault key wrapped in ZeroizedData.
    ///   - notesFallback: If .notes is requested but encryptedNotes is nil,
    ///                    this controls whether to return nil or throw.
    ///
    /// - Returns: ZeroizedData for username / password / notes / otpSecret bytes,
    ///            or decrypted metadata serialized as ZeroizedData blob.
    ///
    /// - Throws: VaultEncryptionError or VaultEntryError.missingCiphertext.
    func decryptField(
        _ field: EntryFieldType,
        vaultKey: ZeroizedData,
        notesFallback: Bool = false
    ) throws -> ZeroizedData {
        switch field {
        case .username:
            return try VaultEncryption.decryptEntry(encryptedUsername.bundle, vaultKey: vaultKey)

        case .password:
            return try VaultEncryption.decryptEntry(encryptedPassword.bundle, vaultKey: vaultKey)

        case .notes:
            guard let notesField = encryptedNotes else {
                if notesFallback {
                    // Return empty ZeroizedData rather than throw.
                    return ZeroizedData(copying: Data())
                }
                throw VaultEntryError.missingCiphertext
            }
            return try VaultEncryption.decryptEntry(notesField.bundle, vaultKey: vaultKey)

        case .otpSecret:
            // OTP secret is not stored directly on VaultEntry.
            // It lives in OTPBlock and is decrypted there.
            throw VaultEntryError.missingCiphertext

        case .metadata:
            guard let metadataField = encryptedMetadata else {
                throw VaultEntryError.missingCiphertext
            }
            return try VaultEncryption.decryptEntry(metadataField.bundle, vaultKey: vaultKey)
        }
    }

    func decryptUsername(vaultKey: ZeroizedData) throws -> ZeroizedData {
        try decryptField(.username, vaultKey: vaultKey)
    }

    func decryptPassword(vaultKey: ZeroizedData) throws -> ZeroizedData {
        try decryptField(.password, vaultKey: vaultKey)
    }

    func decryptNotes(vaultKey: ZeroizedData, allowMissing: Bool = false) throws -> ZeroizedData {
        try decryptField(.notes, vaultKey: vaultKey, notesFallback: allowMissing)
    }

    /// Decrypts and decodes the metadata block into a VaultEntryMetadata struct.
    ///
    /// - Returns: Decoded metadata, or nil if metadata is not present.
    /// - Throws: VaultEntryError if decryption or decoding fails.
    func decryptMetadata(
        vaultKey: ZeroizedData,
        decoder: JSONDecoder = JSONDecoder()
    ) throws -> VaultEntryMetadata? {

        guard encryptedMetadata != nil else { return nil }

        // --- Decrypt blob (catch AES-GCM failure) ---
        let zeroizedBlob: ZeroizedData
        do {
            zeroizedBlob = try decryptField(.metadata, vaultKey: vaultKey)
        } catch {
            // Any AES failure → metadata corruption
            throw VaultEntryError.metadataDecodeFailed
        }

        // --- Extract bytes ---
        let data: Data
        do {
            data = try zeroizedBlob.withBytes { Data($0) }
        } catch {
            throw VaultEntryError.metadataDecodeFailed
        }

        // --- JSON decode ---
        do {
            return try decoder.decode(VaultEntryMetadata.self, from: data)
        } catch {
            throw VaultEntryError.metadataDecodeFailed
        }
    }
}

// MARK: - Metadata Encryption Helper

public extension VaultEntryMetadata {

    /// Helper to encrypt metadata into an EncryptedField.
    ///
    /// This is *not* used automatically by VaultEntry; creation / update flows
    /// should call this explicitly.
    static func encrypt(
        _ metadata: VaultEntryMetadata,
        vaultKey: ZeroizedData,
        now: Date = Date(),
        encoder: JSONEncoder = JSONEncoder()
    ) throws -> EncryptedField {
        let payload = try encoder.encode(metadata)
        let bundle = try VaultEncryption.encryptEntry(plaintext: payload, vaultKey: vaultKey)
        return EncryptedField(bundle: bundle, createdAt: now, updatedAt: now)
    }
}

