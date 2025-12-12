//
//  VaultUnlockEngine.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/10/25.
//

import Foundation

// MARK: - Errors

public enum VaultUnlockError: Error, Equatable {
    case missingVaultFile
    case invalidPassword
    case corruptedVault
    case modelDecodeFailed
}

/// Result of a successful unlock.
/// You can feed this into your existing DecryptedVault initializer/factory.
public struct VaultUnlockResult: Sendable {
    public let header: VaultFileHeader
    public let model: VaultModelV1
    public let vaultKey: ZeroizedData
}

// MARK: - Unlock Engine

public final class VaultUnlockEngine {

    private let vaultURL: URL
    private let keyBundle: VaultKeyBundleV1
    private let fileManager: FileManager

    /// Injectable loader used to fetch the raw vault file bytes.
    /// In production, this reads from disk. In tests, we can inject arbitrary data.
    private let fileLoader: () throws -> Data

    /// - Parameters:
    ///   - vaultURL: Location of the encrypted vault file on disk.
    ///   - keyBundle: VaultKeyBundleV1 used to recover the AES-GCM vault key from user password.
    ///   - fileManager: for testability/mocking, defaults to `.default`.
    public init(
        vaultURL: URL,
        keyBundle: VaultKeyBundleV1,
        fileManager: FileManager = .default
    ) {
        self.vaultURL = vaultURL
        self.keyBundle = keyBundle
        self.fileManager = fileManager

        // Production loader: read from disk using VaultFileIO
        self.fileLoader = { try VaultFileIO.readVaultRequired(at: vaultURL, fileManager: fileManager) }
    }

    /// Internal/test-only initializer that lets us inject arbitrary vault bytes
    /// without hitting the filesystem at all.
    ///
    /// Used by unit tests to simulate corrupted vault files safely.
    init(
        fileLoader: @escaping () throws -> Data,
        keyBundle: VaultKeyBundleV1
    ) {
        self.vaultURL = URL(fileURLWithPath: "/dev/null") // unused in this mode
        self.keyBundle = keyBundle
        self.fileManager = .default
        self.fileLoader = fileLoader
    }

    /// Unlocks the vault using the provided password.
    ///
    /// Pipeline:
    /// - Read vault file from disk (or injected loader)
    /// - Decode header + ciphertext (`VaultSerialization.decodeVaultFile`)
    /// - Derive vault key from password + bundle (`VaultKeyDerivation.decryptVaultKeyV1`)
    /// - Decrypt VaultModelV1 JSON (`VaultEncryption.decryptEntry`)
    /// - Decode `VaultModelV1`
    ///
    /// NOTE: This returns a low-level `VaultUnlockResult`. You can wrap this into
    /// your DecryptedVault at a higher layer.
    public func unlockVault(password: ZeroizedData) throws -> VaultUnlockResult {

        // 1) Read vault file (from disk in production, injected in tests)
        let fileData: Data
        do {
            fileData = try fileLoader()
        } catch let ioError as VaultFileIOError {
            switch ioError {
            case .missingFile:
                throw VaultUnlockError.missingVaultFile
            default:
                throw VaultUnlockError.corruptedVault
            }
        } catch {
            throw VaultUnlockError.corruptedVault
        }

        // 2) Decode header + ciphertext (structural + integrity validation)
        let header: VaultFileHeader
        let bundle: VaultCiphertext
        do {
            let decoded = try VaultSerialization.decodeVaultFile(fileData)
            header = decoded.header
            bundle = decoded.ciphertext
        } catch is VaultFileHeaderError {
            throw VaultUnlockError.corruptedVault
        } catch is VaultSerializationError {
            throw VaultUnlockError.corruptedVault
        } catch {
            throw VaultUnlockError.corruptedVault
        }

        // 3) Derive vault key from password + bundle using Argon2id
        let vaultKey: ZeroizedData
        do {
            // Convert ZeroizedData → Data for the KDF. We do ONE copy and the ZeroizedData will
            // still be wiped on its own lifecycle.
            let passwordData = try password.withBytes { Data($0) }
            vaultKey = try VaultKeyDerivation.decryptVaultKeyV1(
                from: keyBundle,
                password: passwordData
            )
        } catch let kdfError as VaultKeyDerivationError {
            switch kdfError {
            case .invalidPassword:
                throw VaultUnlockError.invalidPassword
            default:
                throw VaultUnlockError.corruptedVault
            }
        } catch {
            throw VaultUnlockError.corruptedVault
        }

        // 4) Decrypt AES-GCM blob into JSON bytes
        let jsonZeroized: ZeroizedData
        do {
            jsonZeroized = try VaultEncryption.decryptEntry(bundle, vaultKey: vaultKey)
        } catch {
            throw VaultUnlockError.corruptedVault
        }

        // 5) Decode VaultModelV1 from JSON
        let model: VaultModelV1
        do {
            let jsonData = try jsonZeroized.withBytes { Data($0) }
            let decoder = JSONDecoder()
            model = try decoder.decode(VaultModelV1.self, from: jsonData)
        } catch {
            throw VaultUnlockError.modelDecodeFailed
        }

        return VaultUnlockResult(header: header, model: model, vaultKey: vaultKey)
    }
}
