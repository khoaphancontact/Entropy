//
//  VaultAutofillAdapter.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  VaultAutofillAdapter.swift
//  Entropy
//
//  Placeholder adapter that defines the boundary between the
//  vault model (Step 2) and the Autofill subsystem.
//
//  Responsibility (when implemented):
//  - Take a VaultEntry (full model) from the main app.
//  - Perform partial decryption of the password field only.
//  - Re-encrypt that password into a minimal AutofillPasswordPayload
//    for IPC to the Autofill extension.
//  - NEVER expose plaintext outside SecurityKit/ZeroizedData closures.
//

import Foundation

/// Errors that may occur when creating Autofill payloads from vault data.
public enum VaultAutofillAdapterError: Error, Equatable {
    /// Autofill adapter logic has not been implemented yet.
    case notImplemented

    /// The requested entry could not be found in the vault.
    case entryNotFound

    /// The entry does not contain a password field suitable for Autofill.
    case noPasswordField

    /// Optional: domain mismatch or entry not valid for requested domain.
    case domainNotAllowed
}

/// Protocol defining the interface for producing Autofill-ready payloads
/// from higher-level vault models.
///
/// The implementation of this protocol will live in Step 2 (VaultModels + VaultManager).
/// For Step 1, we only lock in the boundary and return a deterministic error.
public protocol VaultAutofillAdapting: Sendable {

    /// Creates a minimal AutofillPasswordPayload for a given vault entry.
    ///
    /// - Parameters:
    ///   - entryID: The logical identifier of the vault entry.
    ///   - requestedDomain: Optional domain for which the autofill was requested
    ///                      (e.g., "google.com"). Implementations may use this
    ///                      to filter or reject entries via `.domainNotAllowed`.
    /// - Returns: A fully encrypted `AutofillPasswordPayload` that can be
    ///            safely sent to the Autofill extension.
    /// - Throws: `VaultAutofillAdapterError` or implementation-specific errors.
    func makePasswordPayload(
        for entryID: UUID,
        requestedDomain: String?
    ) throws -> AutofillPasswordPayload
}

/// A placeholder implementation used during Step 1.
/// All calls deterministically fail with `.notImplemented`.
///
/// This exists so that higher-level components can depend
/// on a concrete type without any vault-model logic being ready yet.
public struct PlaceholderVaultAutofillAdapter: VaultAutofillAdapting {

    public init() {}

    public func makePasswordPayload(
        for entryID: UUID,
        requestedDomain: String?
    ) throws -> AutofillPasswordPayload {
        // In Step 2, this will:
        // - Look up the VaultEntry by entryID
        // - Validate domain vs requestedDomain (if provided)
        // - Partially decrypt only the password field via VaultEncryption
        // - Wrap it into an EncryptedPayload/AutofillPasswordPayload
        throw VaultAutofillAdapterError.notImplemented
    }
}
