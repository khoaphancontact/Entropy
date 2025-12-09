//
//  VaultModelHardening.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultModelHardening.swift
//  EntropyVaultModels
//

import Foundation

/// Structural validation errors for the vault model.
public enum VaultHardeningError: Error, Equatable {
    case duplicateFolderID(UUID)
    case mismatchedEntryKey(expectedKey: UUID, actualID: UUID)
    case mismatchedOTPBlockKey(expectedKey: UUID, actualID: UUID)
    case folderReferencesMissingEntry(folderID: UUID, entryID: UUID)
    case orphanedEntry(entryID: UUID)
    case missingUnfiledFolder
    case invalidEntryTimestamps(entryID: UUID)
}

public extension VaultModelV1 {

    /// Perform structural / referential integrity checks on the in-memory model.
    ///
    /// This does NOT decrypt anything; it only validates:
    /// - dictionary key ↔ value.id consistency
    /// - folder ID uniqueness
    /// - folder → entry references
    /// - orphaned entries (entries not referenced by any folder)
    /// - presence of an "Unfiled" folder
    /// - basic timestamp sanity: createdAt <= updatedAt
    func validateHardening() throws {
        try validateEntryKeyConsistency()
        try validateOTPKeyConsistency()
        try validateFolderIDsUnique()
        try validateFolderReferences()
        try validateNoOrphanedEntries()
        try validateUnfiledFolderExists()
        try validateEntryTimestamps()
    }

    // MARK: - Internal helpers

    private func validateEntryKeyConsistency() throws {
        for (key, entry) in entries {
            if key != entry.id {
                throw VaultHardeningError.mismatchedEntryKey(
                    expectedKey: key,
                    actualID: entry.id
                )
            }
        }
    }

    private func validateOTPKeyConsistency() throws {
        for (key, block) in otpBlocks {
            if key != block.id {
                throw VaultHardeningError.mismatchedOTPBlockKey(
                    expectedKey: key,
                    actualID: block.id
                )
            }
        }
    }

    private func validateFolderIDsUnique() throws {
        var seen = Set<UUID>()
        for folder in folders {
            if seen.contains(folder.id) {
                throw VaultHardeningError.duplicateFolderID(folder.id)
            }
            seen.insert(folder.id)
        }
    }

    private func validateFolderReferences() throws {
        let entryIDs = Set(entries.keys)

        for folder in folders {
            for entryID in folder.entries {
                if !entryIDs.contains(entryID) {
                    throw VaultHardeningError.folderReferencesMissingEntry(
                        folderID: folder.id,
                        entryID: entryID
                    )
                }
            }
        }
    }

    private func validateNoOrphanedEntries() throws {
        var referenced = Set<UUID>()
        for folder in folders {
            for id in folder.entries {
                referenced.insert(id)
            }
        }

        for id in entries.keys {
            if !referenced.contains(id) {
                throw VaultHardeningError.orphanedEntry(entryID: id)
            }
        }
    }

    private func validateUnfiledFolderExists() throws {
        // Simple rule: at least one folder named exactly "Unfiled" must exist.
        guard folders.contains(where: { $0.name == "Unfiled" }) else {
            throw VaultHardeningError.missingUnfiledFolder
        }
    }

    private func validateEntryTimestamps() throws {
        for (_, entry) in entries {
            if entry.createdAt > entry.updatedAt {
                throw VaultHardeningError.invalidEntryTimestamps(entryID: entry.id)
            }
        }
    }
}
