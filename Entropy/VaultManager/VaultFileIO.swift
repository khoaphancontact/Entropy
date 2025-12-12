//
//  VaultFileIOError.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/10/25.
//


//
//  VaultFileIO.swift
//  EntropyVault
//
//  Created by Khoa Phan (Home) on 12/xx/25.
//

import Foundation

// MARK: - Errors

public enum VaultFileIOError: Error {
    case missingFile
    case truncatedWrite
    case ioError(underlying: Error)
}

// Equatable conformance (ignores underlying error)
extension VaultFileIOError: Equatable {
    public static func == (lhs: VaultFileIOError, rhs: VaultFileIOError) -> Bool {
        switch (lhs, rhs) {
        case (.missingFile, .missingFile): return true
        case (.truncatedWrite, .truncatedWrite): return true
        case (.ioError, .ioError): return true
        default: return false
        }
    }
}

// MARK: - Vault File I/O

/// Low-level filesystem operations for reading & writing the encrypted vault file.
///
/// All write operations must be *atomic* and permission-restricted.
/// Reads must fail gracefully on missing files (fresh install).
public enum VaultFileIO {

    // MARK: - Existence

    /// Check whether a vault file exists at the given path.
    public static func vaultExists(
        at url: URL,
        fileManager: FileManager = .default
    ) -> Bool {
        fileManager.fileExists(atPath: url.path)
    }

    // MARK: - Read

    /// Read vault file if it exists. Returns `nil` if it doesn't (fresh install).
    public static func readVaultIfExists(
        at url: URL,
        fileManager: FileManager = .default
    ) throws -> Data? {

        guard fileManager.fileExists(atPath: url.path) else {
            return nil
        }

        do {
            return try Data(contentsOf: url, options: [.mappedIfSafe])
        } catch {
            throw VaultFileIOError.ioError(underlying: error)
        }
    }

    /// Read vault file or throw `missingFile`.
    public static func readVaultRequired(
        at url: URL,
        fileManager: FileManager = .default
    ) throws -> Data {

        guard fileManager.fileExists(atPath: url.path) else {
            throw VaultFileIOError.missingFile
        }

        do {
            return try Data(contentsOf: url, options: [.mappedIfSafe])
        } catch {
            throw VaultFileIOError.ioError(underlying: error)
        }
    }

    // MARK: - Atomic Write

    /// Atomically write the vault file to disk.
    ///
    /// Process:
    /// 1. Create temp file in the same directory
    /// 2. Write plaintext bytes
    /// 3. Apply restrictive permissions & file protection
    /// 4. Atomically replace the original vault file
    ///
    /// If anything fails, temp file is removed and the vault is left untouched.
    public static func writeVaultFile(
        _ data: Data,
        to url: URL,
        fileManager: FileManager = .default
    ) throws {

        let directory = url.deletingLastPathComponent()

        // Ensure directory exists
        if !fileManager.fileExists(atPath: directory.path) {
            do {
                try fileManager.createDirectory(
                    at: directory,
                    withIntermediateDirectories: true,
                    attributes: [
                        .posixPermissions: NSNumber(value: Int16(0o700)),
                        .protectionKey: FileProtectionType.complete
                    ]
                )
            } catch {
                throw VaultFileIOError.ioError(underlying: error)
            }
        }

        // Temp file inside same directory → atomic rename guarantee
        let tempFileName = "." + url.lastPathComponent + ".tmp-\(UUID().uuidString)"
        let tempURL = directory.appendingPathComponent(tempFileName)

        do {
            // Write unprotected temp file
            try data.write(to: tempURL, options: [])

            // Lock down permissions & enable iOS protection
            try fileManager.setAttributes(
                [
                    .posixPermissions: NSNumber(value: Int16(0o600)),
                    .protectionKey: FileProtectionType.complete
                ],
                ofItemAtPath: tempURL.path
            )

            // Atomic replace or move
            if fileManager.fileExists(atPath: url.path) {
                _ = try fileManager.replaceItemAt(
                    url,
                    withItemAt: tempURL,
                    backupItemName: nil,
                    options: [.usingNewMetadataOnly]
                )
            } else {
                try fileManager.moveItem(at: tempURL, to: url)
            }

        } catch {
            // Clean up temp file on failure
            try? fileManager.removeItem(at: tempURL)
            throw VaultFileIOError.ioError(underlying: error)
        }
    }
}
