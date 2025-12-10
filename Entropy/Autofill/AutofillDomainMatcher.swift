//
//  AutofillDomainMatcher.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/9/25.
//

//
//  AutofillDomainMatcher.swift
//  EntropyVaultModels
//

import Foundation

/// Options that control how strict domain matching should be.
public struct DomainMatchOptions: Sendable, Equatable {
    /// If true, allow "sub.example.com" to match "example.com".
    public let allowSubdomains: Bool

    public init(allowSubdomains: Bool = false) {
        self.allowSubdomains = allowSubdomains
    }
}

/// Domain-matching utility used before decrypting anything.
/// Ensures that `VaultEntry.domain` is appropriate for the site requesting autofill.
public enum AutofillDomainMatcher {

    /// Main API.
    ///
    /// - Parameters:
    ///   - entryDomain: canonical domain stored in VaultEntry (e.g., "google.com").
    ///   - requestDomain: host or URL from which autofill is requested
    ///                    (e.g., "accounts.google.com" or "https://accounts.google.com/login").
    ///   - options: strict or relaxed mode.
    ///
    /// Rules:
    /// - exact match → OK
    /// - subdomain match → allowed only if `options.allowSubdomains == true`
    /// - no naive substring matching (prevents `apple.com` == `apple.com.evil.co`)
    /// - simple normalization (trim + lowercase + URL host extraction)
    public static func matches(
        entryDomain: String,
        requestDomain: String,
        options: DomainMatchOptions = DomainMatchOptions()
    ) -> Bool {

        guard let entry = normalizeDomain(entryDomain),
              let req = normalizeDomain(requestDomain) else {
            return false
        }

        // 1) Exact match
        if entry == req { return true }

        // 2) Subdomain match (optional)
        if options.allowSubdomains {
            // Require req to end with "." + entry to avoid "evil-example.com".
            if req.hasSuffix("." + entry) {
                return true
            }
        }

        // 3) Otherwise, reject
        return false
    }

    // MARK: - Helpers

    /// Normalize raw input into a canonical host:
    /// - trims whitespace
    /// - lowercases
    /// - if it's a full URL, extract `.host`
    private static func normalizeDomain(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        // Try to treat it as a URL first
        if let url = URL(string: trimmed), let host = url.host, !host.isEmpty {
            return host.lowercased()
        }

        // Fall back to using it as a bare domain
        return trimmed.lowercased()
    }
}
