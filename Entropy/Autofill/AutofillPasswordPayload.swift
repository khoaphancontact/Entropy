//
//  AutofillPasswordPayload.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  AutofillPasswordPayload.swift
//  Entropy
//
//  Minimal encrypted payload for Autofill extension.
//  Never contains plaintext. Designed for IPC between app and extension.
//

import Foundation

/// A minimal, hardened representation of a vault entry's password payload
/// intended solely for secure IPC between the main app and the Autofill extension.
///
/// This structure *never* contains a plaintext password.
/// All sensitive material is inside `encryptedPassword` which must be
/// decrypted only inside the extension using VaultEncryption + ZeroizedData.
public struct AutofillPasswordPayload: Codable, Sendable {

    /// Payload format version — allows forward migration.
    public static let currentVersion = 1

    /// Monotonic version for future-proofing.
    public let version: Int

    /// The vault entry's unique identifier.
    public let entryID: UUID

    /// The domain this payload is valid for (optional but highly recommended).
    /// Used for matching autofill requests to stored credentials.
    public let metadata: AutofillMetadata?

    /// The encrypted password bytes (ciphertext + tag).
    /// This is the output of VaultEncryption or EncryptedPayload.
    public let encryptedPassword: Data

    /// The 12-byte AES-GCM nonce.
    public let nonce: Data

    public init(
        entryID: UUID,
        encryptedPassword: Data,
        nonce: Data,
        metadata: AutofillMetadata? = nil
    ) {
        self.version = Self.currentVersion
        self.entryID = entryID
        self.encryptedPassword = encryptedPassword
        self.nonce = nonce
        self.metadata = metadata
    }
}
