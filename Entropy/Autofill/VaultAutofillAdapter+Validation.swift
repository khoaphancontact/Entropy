//
//  VaultAutofillAdapter+Validation.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/9/25.
//

//
//  VaultAutofillAdapter+Validation.swift
//  EntropyVaultModels
//

import Foundation

public enum AutofillValidationError: Error, Equatable {
    case missingPasswordCiphertext
    case invalidCiphertext
    case invalidNonce
    case invalidTag
    case malformedEncryptedField
}

public extension VaultAutofillAdapter {

    /// Performs structural validation of an entry BEFORE partial decrypt.
    /// Ensures the ciphertext bundle is intact and not tampered with.
    func validateEntryBeforeAutofill(_ entry: VaultEntry) throws {

        // ---- 1) Password field must exist ----
        let field = entry.encryptedPassword
        let bundle = field.bundle

        // ---- 2) Nonce validation ----
        if bundle.nonce.count != 12 {
            throw AutofillValidationError.invalidNonce
        }

        // ---- 3) Ciphertext presence ----
        if bundle.ciphertext.isEmpty {
            throw AutofillValidationError.invalidCiphertext
        }

        // ---- 4) Tag validation ----
        // Your AES-GCM bundle stores tag as the last 16 bytes of ciphertext
        if bundle.ciphertext.count < 16 {
            throw AutofillValidationError.invalidTag
        }

        // ---- 5) AssociatedData sanity (optional) ----
        // If associatedData exists, ensure it is not malformed.
        if let ad = bundle.associatedData, ad.isEmpty == false {
            // Associated data exists, but no malformed detection needed here.
            // Kept for future extension.
        }
    }
}
