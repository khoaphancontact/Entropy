//
//  AESGCMContextPool.swift
//  Entropy
//
//  Created by Khoa Phan on 12/6/25.
//

import Foundation

/// A lightweight actor providing a stable API boundary for fast, repeated AES-GCM
/// decrypt operations needed by the Autofill extension.
///
/// For Step 1, this is a thin wrapper over `VaultEncryption.decryptEntry`.
/// In future phases, this actor may:
/// - Pre-allocate CryptoKit AEAD contexts,
/// - Maintain a pool sized to available CPU cores,
/// - Recycle contexts for low-latency decrypt loops.
public actor AESGCMContextPool {

    public init() {}

    /// Synchronous-style decrypt inside the actor.
    ///
    /// - Parameters:
    ///   - bundle: The encrypted vault entry.
    ///   - vaultKey: A `ZeroizedData` container for the symmetric key.
    /// - Returns: A `ZeroizedData` containing the decrypted plaintext.
    /// - Throws: `VaultEncryptionError` if decryption fails.
    public func decrypt(
        _ bundle: VaultCiphertext,
        vaultKey: ZeroizedData
    ) throws -> ZeroizedData {
        try VaultEncryption.decryptEntry(bundle, vaultKey: vaultKey)
    }

    /// Async convenience wrapper. This is async only because it is actor-isolated;
    /// we do not spin up extra tasks here (callers can decide if they want that).
    public func decryptAsync(
        _ bundle: VaultCiphertext,
        vaultKey: ZeroizedData
    ) async throws -> ZeroizedData {
        // Safe: this runs inside the actor’s isolation context
        try decrypt(bundle, vaultKey: vaultKey)
    }
}
