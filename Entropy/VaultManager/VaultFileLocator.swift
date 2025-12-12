//
//  VaultFileLocator.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/10/25.
//


//
//  VaultFileLocator.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/xx/25.
//

import Foundation

/// Responsible for computing the on-disk location of the primary vault file.
/// Step 4 (multi-vault) will layer on top of this.
public enum VaultFileLocator {

    private enum Constants {
        static let vaultDirectoryName = "Vaults"
        static let vaultFileName = "Vault.entropyvault"
    }

    /// Application Support/Vaults
    public static func vaultDirectoryURL(
        fileManager: FileManager = .default
    ) throws -> URL {
        let base = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )

        let dir = base.appendingPathComponent(Constants.vaultDirectoryName, isDirectory: true)

        // Ensure directory exists
        if !fileManager.fileExists(atPath: dir.path) {
            try fileManager.createDirectory(
                at: dir,
                withIntermediateDirectories: true,
                attributes: [
                    .posixPermissions: NSNumber(value: Int16(0o700)),
                    .protectionKey: FileProtectionType.complete
                ]
            )
        }

        return dir
    }

    /// Full path to the primary vault file.
    public static func vaultFileURL(
        fileManager: FileManager = .default
    ) throws -> URL {
        let dir = try vaultDirectoryURL(fileManager: fileManager)
        return dir.appendingPathComponent(Constants.vaultFileName, isDirectory: false)
    }
}
