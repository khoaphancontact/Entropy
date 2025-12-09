//
//  VaultEntrySecurityInfo.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  VaultEntrySecurityInfo.swift
//  EntropyVaultModels
//

import Foundation

/// Security-related metadata for a single vault entry.
///
/// This is stored INSIDE the encrypted VaultEntry and never contains
/// raw plaintext passwords. The `passwordFingerprint` is a hash of the
/// password, used ONLY for detecting reuse across entries.
public struct VaultEntrySecurityInfo: Codable, Equatable, Sendable {

    /// Overall strength bucket for the password (Milestone M stub-backed).
    public var strength: PasswordStrength

    /// Optional numeric score (0–100 or similar), if computed.
    public var score: Int?

    /// Estimated entropy in bits, if computed.
    public var entropyBits: Double?

    /// When this entry was last evaluated for strength/reuse.
    public var lastEvaluated: Date

    /// Encrypted SHA-256 fingerprint of the password.
    ///
    /// - Computed ONLY inside VaultManager.unlockVault() using the decrypted
    ///   password bytes and SHA-256.
    /// - Stored encrypted along with other fields inside VaultEntry.
    /// - Used to detect reused passwords across entries without decrypting
    ///   every password repeatedly.
    /// - Optional for backward compatibility.
    public var passwordFingerprint: Data?

    // MARK: - Init

    public init(
        strength: PasswordStrength,
        score: Int? = nil,
        entropyBits: Double? = nil,
        lastEvaluated: Date = Date(),
        passwordFingerprint: Data? = nil
    ) {
        self.strength = strength
        self.score = score
        self.entropyBits = entropyBits
        self.lastEvaluated = lastEvaluated
        self.passwordFingerprint = passwordFingerprint
    }
}
