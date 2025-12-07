//
//  EntryFieldTypes.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  EntryFieldTypes.swift
//  EntropyVaultModels
//

import Foundation

/// Identifies which logical field of a VaultEntry is being accessed or decrypted.
/// Used for partial-decrypt paths and Autofill routing.
public enum EntryFieldType: String, Codable, CaseIterable, Sendable {
    case username
    case password
    case notes
    case otpSecret
    case metadata
}
