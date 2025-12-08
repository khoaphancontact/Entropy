//
//  DecryptedVaultEntry.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  DecryptedVaultEntry.swift
//  EntropyVaultModels
//

import Foundation

/// In-memory decrypted view of a single vault entry.
/// All sensitive fields are wrapped in ZeroizedData and must be wiped
/// when the entry is no longer needed.
public final class DecryptedVaultEntry {

    // MARK: - Identity & metadata

    public let id: UUID
    public let title: String
    public let domain: String?
    public let createdAt: Date
    public let updatedAt: Date

    // MARK: - Decrypted secrets

    public let username: ZeroizedData
    public let password: ZeroizedData
    public let notes: ZeroizedData?
    public let otpSecret: ZeroizedData?

    // MARK: - Non-secret metadata

    /// Decrypted usage metadata (timestamps only).
    public let metadata: VaultEntryMetadata?

    /// Security scoring info (strength, entropy, reuse fingerprint, etc.).
    public let securityInfo: VaultEntrySecurityInfo?

    // MARK: - Init (internal to module)

    public init(
        id: UUID,
        title: String,
        domain: String?,
        createdAt: Date,
        updatedAt: Date,
        username: ZeroizedData,
        password: ZeroizedData,
        notes: ZeroizedData?,
        otpSecret: ZeroizedData?,
        metadata: VaultEntryMetadata?,
        securityInfo: VaultEntrySecurityInfo?
    ) {
        self.id = id
        self.title = title
        self.domain = domain
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.username = username
        self.password = password
        self.notes = notes
        self.otpSecret = otpSecret
        self.metadata = metadata
        self.securityInfo = securityInfo
    }

    deinit {
        // Belt-and-suspenders: explicitly wipe on deinit as well.
        wipeSensitiveData()
    }

    // MARK: - Wiping

    /// Wipes all decrypted secrets. Safe to call multiple times.
    public func wipeSensitiveData() {
        username.wipe()
        password.wipe()
        notes?.wipe()
        otpSecret?.wipe()
    }
}

// MARK: - Factory from encrypted models

public extension DecryptedVaultEntry {

    /// Build a DecryptedVaultEntry from an encrypted VaultEntry and optional OTPBlock.
    ///
    /// This is the canonical mapping used by VaultManager.unlockVault()
    /// (Step 3), but it lives here so Step 2 tests can validate the shape.
    static func from(
        entry: VaultEntry,
        otpBlock: OTPBlock?,
        vaultKey: ZeroizedData
    ) throws -> DecryptedVaultEntry {

        let username = try entry.decryptUsername(vaultKey: vaultKey)
        let password = try entry.decryptPassword(vaultKey: vaultKey)

        let notes: ZeroizedData?
        if let _ = entry.encryptedNotes {
            notes = try entry.decryptNotes(vaultKey: vaultKey, allowMissing: false)
        } else {
            notes = nil
        }

        let otpSecret: ZeroizedData?
        if let otpID = entry.otpBlockID, let block = otpBlock, block.id == otpID {
            otpSecret = try block.decryptSecret(vaultKey: vaultKey)
        } else {
            otpSecret = nil
        }

        let metadata = try entry.decryptMetadata(vaultKey: vaultKey)
        let securityInfo = entry.securityInfo

        return DecryptedVaultEntry(
            id: entry.id,
            title: entry.title,
            domain: entry.domain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            username: username,
            password: password,
            notes: notes,
            otpSecret: otpSecret,
            metadata: metadata,
            securityInfo: securityInfo
        )
    }
}
