//
//  AutofillMetadata.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  AutofillMetadata.swift
//  Entropy
//
//  Non-sensitive supplemental metadata used for Autofill matching.
//

import Foundation

/// Non-sensitive metadata used by the Autofill extension to determine
/// whether a particular encrypted password payload is relevant for
/// the requesting domain/URL.
///
/// All fields are optional and must never contain decrypted secrets.
public struct AutofillMetadata: Codable, Sendable, Equatable {

    /// The domain associated with this credential (e.g., "google.com").
    public let domain: String?

    /// Optional username hint (non-secret). This is *not* the decrypted username.
    /// It is safe because it's not used to authenticate anything and does not
    /// reveal vault contents meaningfully. May be omitted entirely.
    public let displayUsername: String?

    /// Optional timestamp for debugging/matching/logical expiration use.
    public let lastModified: Date?

    public init(
        domain: String? = nil,
        displayUsername: String? = nil,
        lastModified: Date? = nil
    ) {
        self.domain = domain
        self.displayUsername = displayUsername
        self.lastModified = lastModified
    }
}
