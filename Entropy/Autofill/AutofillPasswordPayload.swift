//
//  AutofillPasswordPayload.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//
//
//  AutofillPasswordPayload.swift
//  EntropyVaultModels
//

import Foundation

/// Decrypted, in-memory payload used for Autofill flows.
///
/// This NEVER leaves the process and should only be stored in
/// AutofillEphemeralMemory or similarly short-lived contexts.
public struct AutofillPasswordPayload: Sendable {

    /// Stable ID of the vault entry this payload came from.
    public let entryID: UUID

    /// Optional decrypted username (may be nil if not needed or not decrypted).
    public let username: ZeroizedData?

    /// Decrypted password (wrapped in ZeroizedData).
    public let password: ZeroizedData

    /// Domain the payload is intended for (already validated by caller or J1).
    public let domain: String

    /// When this entry was originally created.
    public let createdAt: Date

    /// When this entry was last modified.
    public let updatedAt: Date

    public init(
        entryID: UUID,
        username: ZeroizedData?,
        password: ZeroizedData,
        domain: String,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.entryID = entryID
        self.username = username
        self.password = password
        self.domain = domain
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}
