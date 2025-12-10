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


import Foundation

public enum AutofillAdapterError: Error, Equatable {
    case domainMismatch
}

public struct VaultAutofillAdapter: Sendable {

    public init() {}

    /// Full autofill pipeline combining:
    /// - J1: domain matching
    /// - J4: entry structural validation
    /// - J2: partial password decrypt
    /// - J3: payload construction
    public func autofillPayload(
        for entry: VaultEntry,
        requestDomain: String,
        vaultKey: ZeroizedData,
        options: DomainMatchOptions = DomainMatchOptions()
    ) throws -> AutofillPasswordPayload {

        // STEP 0 — domain must exist on entry
        guard let entryDomain = entry.domain else {
            throw AutofillAdapterError.domainMismatch
        }

        // STEP 1 — Domain check (J1)
        guard AutofillDomainMatcher.matches(
            entryDomain: entryDomain,
            requestDomain: requestDomain,
            options: options
        ) else {
            throw AutofillAdapterError.domainMismatch
        }

        // STEP 2 — Validate encrypted structure (J4)
        try validateEntryBeforeAutofill(entry)

        // STEP 3 — Partial decrypt of password (J2)
        let password = try entry.decryptPasswordOnly(vaultKey: vaultKey)

        // STEP 4 — Build payload (J3)
        return AutofillPasswordPayload(
            entryID: entry.id,
            username: nil,
            password: password,
            domain: requestDomain,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt
        )
    }
}
