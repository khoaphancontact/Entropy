//
//  VaultSerialization.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultSerialization.swift
//  EntropyVaultModels
//

import Foundation
import CryptoKit

public enum VaultSerializationError: Error, Equatable {
    case missingCiphertext
    case truncatedCiphertext
    case hashMismatch
}

/// Responsible for encoding/decoding the full vault file.
/// Layout:
/// [ VaultFileHeader (magic + wrapper + JSON) ] + [ JSON-encoded VaultCiphertext ]
public struct VaultSerialization {

    // MARK: - Encode vault to Data

    /// Encode a complete vault file from:
    /// - header (without integrity hash set)
    /// - plaintext payload (already-encoded VaultModelV1 JSON in Milestone G)
    /// - vaultKey used for AES-GCM
    public static func encodeVaultFile(
        header: VaultFileHeader,
        plaintext: Data,
        vaultKey: ZeroizedData
    ) throws -> Data {

        // 1) Encrypt payload using AES-GCM (single blob)
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: plaintext,
            vaultKey: vaultKey
        )

        let ciphertext = bundle.ciphertext

        // 2) Compute integrity hash = SHA-256(ciphertext)
        let integrity = Data(SHA256.hash(data: ciphertext))

        // 3) Build updated header with integrity hash and updated modifiedAt
        let updatedHeader = VaultFileHeader(
            vaultVersion: header.vaultVersion,
            schemaVersion: header.schemaVersion,
            createdAt: header.createdAt,
            modifiedAt: Date(),
            encryptionMethod: header.encryptionMethod,
            kdfParams: header.kdfParams,
            integrityHash: integrity
        )

        // 4) Encode header (magic + wrapper + JSON body)
        let headerData = try updatedHeader.encodeToData()

        // 5) Encode ciphertext bundle as deterministic JSON
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let cipherJSON = try encoder.encode(bundle)

        // 6) Final layout: [headerData] + [cipherJSON]
        var file = Data()
        file.append(headerData)
        file.append(cipherJSON)
        return file
    }

    // MARK: - Decode vault from Data

    /// Decode a vault file into its header and encrypted blob.
    /// Does NOT decrypt the inner model; only validates integrity.
    public static func decodeVaultFile(
        _ data: Data
    ) throws -> (header: VaultFileHeader, ciphertext: VaultCiphertext) {

        // 1) Decode header (structural + semantic validation)
        let header = try VaultFileHeader.decode(from: data)

        // 2) Find where header ends so we can isolate ciphertext JSON
        let headerLength = try extractHeaderBodyLength(from: data)
        let headerTotal = VaultFileHeader.magic.count + 1 + 4 + headerLength

        guard headerTotal <= data.count else {
            throw VaultSerializationError.truncatedCiphertext
        }

        let remaining = data.dropFirst(headerTotal)
        guard !remaining.isEmpty else {
            throw VaultSerializationError.missingCiphertext
        }

        // 3) Decode VaultCiphertext from remaining JSON
        let decoder = JSONDecoder()
        let bundle: VaultCiphertext
        do {
            bundle = try decoder.decode(VaultCiphertext.self, from: remaining)
        } catch {
            throw VaultSerializationError.truncatedCiphertext
        }

        // 4) Verify integrity hash
        let computed = Data(SHA256.hash(data: bundle.ciphertext))
        guard computed == header.integrityHash else {
            throw VaultSerializationError.hashMismatch
        }

        return (header, bundle)
    }

    // MARK: - Helper: extract header body length from raw bytes

    /// Reads the header body length from the header wrapper.
    /// Layout:
    /// magic[4] + version[1] + length[4] + body[length]
    private static func extractHeaderBodyLength(from data: Data) throws -> Int {
        let baseOffset = VaultFileHeader.magic.count + 1  // magic + headerFormatVersion
        let lengthRange = baseOffset ..< (baseOffset + 4)

        guard lengthRange.upperBound <= data.count else {
            throw VaultSerializationError.truncatedCiphertext
        }

        let bytes = Array(data[lengthRange])
        let len =
            (UInt32(bytes[0]) << 24) |
            (UInt32(bytes[1]) << 16) |
            (UInt32(bytes[2]) << 8)  |
             UInt32(bytes[3])

        return Int(len)
    }
}
