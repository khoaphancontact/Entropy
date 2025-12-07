//
//  AutofillEphemeralMemory.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  AutofillEphemeralMemory.swift
//  Entropy
//
//  Ephemeral in-memory store for decrypted AutofillEntry objects.
//  Used by the app and autofill extensions to hold secrets briefly,
//  then wipe them once used or expired.
//

import Foundation

/// Errors thrown by AutofillEphemeralMemory.
public enum AutofillEphemeralMemoryError: Error, Equatable {
    /// No entry was found for the given identifier.
    case entryNotFound
    /// The entry exists but is expired and has been wiped.
    case entryExpired
}

/// Actor that holds decrypted AutofillEntry instances in memory
/// for a short, controlled period of time.
///
/// Security properties:
/// - Entries are never written to disk.
/// - All secrets are stored in AutofillEntry, which uses ZeroizedData.
/// - Once removed from this actor, entries are released and ZeroizedData
///   will wipe its buffers on deinit.
/// - Expiration is enforced on every read; expired entries are not returned.
public actor AutofillEphemeralMemory {

    /// A single stored entry with expiration metadata.
    private struct StoredEntry {
        let entry: AutofillEntry
        let expiresAt: Date
    }

    /// In-memory map of entryID → StoredEntry.
    private var entries: [UUID: StoredEntry] = [:]

    /// Default TTL for stored entries (seconds).
    public static let defaultTTL: TimeInterval = 15

    public init() {}

    // MARK: - Store

    /// Stores an AutofillEntry in ephemeral memory with a given TTL.
    ///
    /// - Parameters:
    ///   - entry: The decrypted autofill entry to store.
    ///   - ttl: Time interval in seconds before the entry is considered expired.
    ///          Defaults to `defaultTTL`.
    ///
    /// If an entry with the same `entry.entryID` already exists, it is overwritten.
    public func store(_ entry: AutofillEntry, ttl: TimeInterval = AutofillEphemeralMemory.defaultTTL) {
        let now = Date()
        let expiresAt = now.addingTimeInterval(ttl)
        entries[entry.entryID] = StoredEntry(entry: entry, expiresAt: expiresAt)
    }

    // MARK: - Fetch / Consume

    /// Fetches an AutofillEntry by id, if present and not expired, without removing it.
    ///
    /// - Parameter entryID: The entry identifier.
    /// - Returns: The stored AutofillEntry if valid.
    /// - Throws: `AutofillEphemeralMemoryError.entryNotFound` or `.entryExpired`.
    @discardableResult
    public func peek(entryID: UUID, at date: Date = Date()) throws -> AutofillEntry {
        guard let stored = entries[entryID] else {
            throw AutofillEphemeralMemoryError.entryNotFound
        }

        if stored.expiresAt <= date {
            // Wipe expired entry
            entries.removeValue(forKey: entryID)
            throw AutofillEphemeralMemoryError.entryExpired
        }

        return stored.entry
    }

    /// Fetches and consumes an AutofillEntry by id.
    ///
    /// On success, the entry is removed from memory and will not be returned again.
    ///
    /// - Parameter entryID: The entry identifier.
    /// - Returns: The stored AutofillEntry if valid.
    /// - Throws: `AutofillEphemeralMemoryError.entryNotFound` or `.entryExpired`.
    public func fetchAndConsume(entryID: UUID, at date: Date = Date()) throws -> AutofillEntry {
        guard let stored = entries[entryID] else {
            throw AutofillEphemeralMemoryError.entryNotFound
        }

        // Always remove the entry from memory on fetch attempt
        entries.removeValue(forKey: entryID)

        if stored.expiresAt <= date {
            throw AutofillEphemeralMemoryError.entryExpired
        }

        return stored.entry
    }

    // MARK: - Domain-based helpers

    /// Returns all non-expired entries whose domain matches the given string
    /// (case-insensitive substring match).
    ///
    /// This is intended for use by Autofill to shortlist likely candidates
    /// for a given URL / domain.
    public func entries(matchingDomain domain: String, at date: Date = Date()) -> [AutofillEntry] {
        guard !domain.isEmpty else { return [] }

        let lower = domain.lowercased()
        var result: [AutofillEntry] = []
        var idsToRemove: [UUID] = []

        for (id, stored) in entries {
            if stored.expiresAt <= date {
                idsToRemove.append(id)
                continue
            }

            if let entryDomain = stored.entry.domain?.lowercased(),
               entryDomain.contains(lower) {
                result.append(stored.entry)
            }
        }

        // Wipe expired as we go.
        for id in idsToRemove {
            entries.removeValue(forKey: id)
        }

        return result
    }

    // MARK: - Lifecycle / Cleanup

    /// Removes all expired entries based on the current time.
    /// Can be called opportunistically on:
    /// - app becoming active
    /// - extension wake
    /// - periodic background tasks (if any)
    public func purgeExpired(at date: Date = Date()) {
        entries = entries.filter { _, stored in
            stored.expiresAt > date
        }
    }

    /// Clears all stored entries immediately.
    /// Call this on:
    /// - app background
    /// - extension deactivation
    /// - explicit "lock now" actions
    public func clearAll() {
        entries.removeAll(keepingCapacity: false)
    }

    /// Returns the current number of entries still tracked (including expired ones
    /// that have not yet been purged). Intended for diagnostics / tests only.
    public func debugCount(includeExpired: Bool = true, at date: Date = Date()) -> Int {
        if includeExpired {
            return entries.count
        }

        return entries.values.filter { $0.expiresAt > date }.count
    }
}
