//
//  VaultFolder.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultFolder.swift
//  EntropyVaultModels
//

import Foundation

/// Represents a single folder grouping for vault entries.
/// Contains *only* UUID references — never decrypted data.
public struct VaultFolder: Codable, Equatable, Identifiable, Sendable {

    // MARK: - Identity

    /// Stable, never-changing identifier for the folder.
    public let id: UUID

    /// Display name of the folder.
    public var name: String

    /// Folder ordering index (0 = first).
    public var orderIndex: Int

    /// Entry IDs belonging to this folder, in deterministic order.
    public private(set) var entries: [UUID]

    // MARK: - Init

    public init(
        id: UUID = UUID(),
        name: String,
        orderIndex: Int,
        entries: [UUID] = []
    ) {
        self.id = id
        self.name = name
        self.orderIndex = orderIndex
        self.entries = entries
    }

    // MARK: - Folder Mutations

    /// Add an entry to the folder (at the end).
    public mutating func addEntry(_ entryID: UUID) {
        // Prevent duplicates (invariant)
        guard !entries.contains(entryID) else { return }
        entries.append(entryID)
    }

    /// Remove an entry from the folder.
    public mutating func removeEntry(_ entryID: UUID) {
        entries.removeAll { $0 == entryID }
    }

    /// Rename folder safely (no side effects).
    public mutating func rename(to newName: String) {
        self.name = newName
    }

    /// Return entries in deterministic order.
    /// This allows consistent ordering in UI or serialization.
    public func orderedEntries() -> [UUID] {
        entries
    }
}
