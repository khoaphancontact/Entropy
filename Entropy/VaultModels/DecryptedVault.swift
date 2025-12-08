//
//  DecryptedVault.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  DecryptedVault.swift
//  EntropyVaultModels
//

import Foundation

/// In-memory decrypted vault snapshot.
/// Contains decrypted entries, folder structure, and header metadata.
/// All sensitive data must be wiped when this object is discarded.
public final class DecryptedVault {

    // MARK: - Metadata

    /// Full header used to describe this vault file.
    public let header: VaultFileHeader

    /// The derived vault key for this snapshot.
    public let vaultKey: ZeroizedData

    /// Decrypted entries.
    public var entries: [DecryptedVaultEntry]

    /// Folder structure (non-secret).
    public var folders: [VaultFolder]

    // MARK: - Init

    public init(
        header: VaultFileHeader,
        vaultKey: ZeroizedData,
        entries: [DecryptedVaultEntry],
        folders: [VaultFolder]
    ) {
        self.header = header
        self.vaultKey = vaultKey
        self.entries = entries
        self.folders = folders
    }

    deinit {
        wipeSensitiveData()
    }

    // MARK: - Wiping

    /// Wipes vault key and all decrypted entry data.
    /// Safe to call multiple times.
    public func wipeSensitiveData() {
        vaultKey.wipe()
        for entry in entries {
            entry.wipeSensitiveData()
        }
    }
}
