//
//  VaultEntry+PartialDecrypt.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/9/25.
//

//
//  VaultEntry+PartialDecrypt.swift
//  EntropyVaultModels
//

import Foundation

/// Partial decryption helpers for VaultEntry.
/// Autofill should ONLY use this for password-only decrypt.
public extension VaultEntry {

    /// Decrypts ONLY the password field.
    /// - Returns: ZeroizedData containing plaintext password bytes.
    /// - Important: All other fields remain encrypted.
    func decryptPasswordOnly(
        vaultKey: ZeroizedData
    ) throws -> ZeroizedData {
        // encryptedPassword is non-optional by model invariants.
        // Field presence is enforced by decoding & VaultModelHardening.
        return try VaultEncryption.decryptEntry(
            encryptedPassword.bundle,
            vaultKey: vaultKey
        )
    }
}
