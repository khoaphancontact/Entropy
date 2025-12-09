//
//  VaultModelV1.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultModelV1.swift
//  EntropyVaultModels
//

import Foundation

/// Errors related to the top-level vault model.
public enum VaultModelError: Error, Equatable {
    case schemaVersionMismatch(expected: UInt16, actual: UInt16)
}

/// Full on-disk logical model for vault version 1.
/// This is the structure that gets JSON-encoded and then AES-GCM encrypted.
public struct VaultModelV1: Codable, Equatable, Sendable {

    // MARK: - Schema / metadata

    /// Schema version for this inner model. Must match VaultFileHeader.schemaVersion.
    public let schemaVersion: UInt16

    /// When this vault was first created.
    public let createdAt: Date

    /// When this vault was last modified (any entry/folder change).
    public var modifiedAt: Date

    // MARK: - Core collections

    /// All entries in the vault, keyed by their stable UUID.
    public var entries: [UUID: VaultEntry]

    /// Folder definitions (non-secret). Must contain at least the “Unfiled” folder.
    public var folders: [VaultFolder]

    /// All OTP blocks, keyed by their UUID.
    public var otpBlocks: [UUID: OTPBlock]

    // MARK: - Init

    public init(
        schemaVersion: UInt16 = VaultFileHeader.currentSchemaVersion,
        createdAt: Date,
        modifiedAt: Date,
        entries: [UUID: VaultEntry],
        folders: [VaultFolder],
        otpBlocks: [UUID: OTPBlock]
    ) {
        self.schemaVersion = schemaVersion
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.entries = entries
        self.folders = folders
        self.otpBlocks = otpBlocks
    }

    /// Convenience constructor for an empty vault with a single “Unfiled” folder.
    public static func empty(
        now: Date = Date(),
        schemaVersion: UInt16 = VaultFileHeader.currentSchemaVersion
    ) -> VaultModelV1 {
        let unfiledFolder = VaultFolder(
            name: "Unfiled",
            orderIndex: 0,
            entries: []
        )

        return VaultModelV1(
            schemaVersion: schemaVersion,
            createdAt: now,
            modifiedAt: now,
            entries: [:],
            folders: [unfiledFolder],
            otpBlocks: [:]
        )
    }
}

// MARK: - Validation

public extension VaultModelV1 {

    /// Ensure that the model's schemaVersion matches the header's schemaVersion.
    func validateSchemaMatches(header: VaultFileHeader) throws {
        guard schemaVersion == header.schemaVersion else {
            throw VaultModelError.schemaVersionMismatch(
                expected: header.schemaVersion,
                actual: schemaVersion
            )
        }
    }
}

// MARK: - Helpers for deterministic encoding

public extension VaultModelV1 {

    /// Recommended encoder for deterministic on-disk layout.
    static func makeJSONEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    static func makeJSONDecoder() -> JSONDecoder {
        JSONDecoder()
    }
}
