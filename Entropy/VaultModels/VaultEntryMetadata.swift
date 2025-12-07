//
//  VaultEntryMetadata.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  VaultEntryMetadata.swift
//  EntropyVaultModels
//

import Foundation

/// Encrypted per-entry usage metadata.
/// This is serialized as JSON and then encrypted into a VaultCiphertext
/// stored on VaultEntry as `encryptedMetadata`.
///
/// None of these fields are required; absence == "unknown".
public struct VaultEntryMetadata: Codable, Equatable, Sendable {
    public let lastCopiedUsername: Date?
    public let lastCopiedPassword: Date?
    public let lastUsedOTP: Date?
    public let lastViewed: Date?

    public init(
        lastCopiedUsername: Date? = nil,
        lastCopiedPassword: Date? = nil,
        lastUsedOTP: Date? = nil,
        lastViewed: Date? = nil
    ) {
        self.lastCopiedUsername = lastCopiedUsername
        self.lastCopiedPassword = lastCopiedPassword
        self.lastUsedOTP = lastUsedOTP
        self.lastViewed = lastViewed
    }
}
