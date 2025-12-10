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

/// Responsible for full vault encoding/decoding.
/// Final layout on disk:
///
///   [ VaultFileHeader (magic + wrapper + JSON) ]
/// + [ JSON-encoded VaultCiphertext ]
///
public enum VaultSerialization {

    // -------------------------------------------------------------------------
    // MARK: - PUBLIC API (Milestone F required)
    // -------------------------------------------------------------------------

    /// Encode a full vault model (VaultModelV1) into the final vault file format.
    ///
    /// This produces:
    ///   header + encrypted JSON payload + integrity hash
    ///
    public static func encode(
        model: VaultModelV1,
        vaultKey: ZeroizedData
    ) throws -> Data {

        // 1) Encode inner VaultModelV1 as JSON
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys] // deterministic
        let plaintext = try encoder.encode(model)

        // 2) Build initial header (integrityHash will be replaced)
        let header = VaultFileHeader(
            vaultVersion: VaultFileHeader.currentVaultVersion,
            schemaVersion: VaultFileHeader.currentSchemaVersion,
            createdAt: model.createdAt,
            modifiedAt: model.modifiedAt,
            encryptionMethod: .aes256GCM,
            kdfParams: defaultKDFParams(),
            integrityHash: Data(repeating: 0, count: VaultFileHeader.integrityHashLength)
        )

        // 3) Delegate to encodeVaultFile
        return try encodeVaultFile(
            header: header,
            plaintext: plaintext,
            vaultKey: vaultKey
        )
    }

    /// Decode a final vault file into a full VaultModelV1.
    /// Validates header, integrity hash, decrypts payload, and JSON-decodes.
    public static func decode(
        from data: Data,
        vaultKey: ZeroizedData
    ) throws -> VaultModelV1 {

        // 1) Decode structural header + ciphertext JSON
        let (header, bundle) = try decodeVaultFile(data)

        // 2) Decrypt AES-GCM payload
        let decrypted = try VaultEncryption.decryptEntry(bundle, vaultKey: vaultKey)


        // 3) Decode JSON → VaultModelV1
        // Convert ZeroizedData → Data for decoding
        let jsonData = try decrypted.withBytes { Data($0) }

        // Now decode JSON into VaultModelV1
        let decoder = JSONDecoder()
        let model = try decoder.decode(VaultModelV1.self, from: jsonData)

        // 4) Validate schema version
        guard model.schemaVersion == VaultFileHeader.currentSchemaVersion else {
            throw VaultFileHeaderError.unsupportedVaultVersion(model.schemaVersion)
        }

        return model
    }

    // -------------------------------------------------------------------------
    // MARK: - INTERNAL API (used by encode/decode)
    // -------------------------------------------------------------------------

    /// Lower-level API used by `encode(model:)`.
    /// Handles encryption and header construction.
    public static func encodeVaultFile(
        header: VaultFileHeader,
        plaintext: Data,
        vaultKey: ZeroizedData
    ) throws -> Data {

        // 1) Encrypt payload as AES-GCM bundle
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: plaintext,
            vaultKey: vaultKey
        )

        // 2) Compute integrity hash = SHA-256(ciphertext)
        let integrity = Data(SHA256.hash(data: bundle.ciphertext))

        // 3) Build updated header with correct integrity hash
        let updatedHeader = VaultFileHeader(
            vaultVersion: header.vaultVersion,
            schemaVersion: header.schemaVersion,
            createdAt: header.createdAt,
            modifiedAt: Date(),
            encryptionMethod: header.encryptionMethod,
            kdfParams: header.kdfParams,
            integrityHash: integrity
        )

        // 4) Encode header to bytes
        let headerData = try updatedHeader.encodeToData()

        // 5) Encode ciphertext bundle as deterministic JSON
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let cipherJSON = try encoder.encode(bundle)

        // 6) Final file structure: [headerData] + [cipherJSON]
        var file = Data()
        file.append(headerData)
        file.append(cipherJSON)
        return file
    }

    /// Lower-level API used by `decode(from:)`.
    /// Parses header + ciphertext JSON and verifies integrity.
    public static func decodeVaultFile(
        _ data: Data
    ) throws -> (header: VaultFileHeader, ciphertext: VaultCiphertext) {

        // 1) Parse header
        let header = try VaultFileHeader.decode(from: data)

        // 2) Determine header total length
        let headerLength = try extractHeaderBodyLength(from: data)
        let headerTotal = VaultFileHeader.magic.count + 1 + 4 + headerLength

        guard headerTotal <= data.count else {
            throw VaultSerializationError.truncatedCiphertext
        }

        // 3) Extract ciphertext JSON
        let remaining = data.dropFirst(headerTotal)
        guard !remaining.isEmpty else {
            throw VaultSerializationError.missingCiphertext
        }

        // 4) Decode VaultCiphertext
        let decoder = JSONDecoder()
        let bundle: VaultCiphertext
        do {
            bundle = try decoder.decode(VaultCiphertext.self, from: remaining)
        } catch {
            throw VaultSerializationError.truncatedCiphertext
        }

        // 5) Verify SHA-256 integrity hash
        let computed = Data(SHA256.hash(data: bundle.ciphertext))
        guard computed == header.integrityHash else {
            throw VaultSerializationError.hashMismatch
        }

        return (header, bundle)
    }

    // -------------------------------------------------------------------------
    // MARK: - Internal Helpers
    // -------------------------------------------------------------------------

    /// Reads the JSON body length from the header wrapper.
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

    /// Default Argon2 parameters for new vaults.
    private static func defaultKDFParams() -> VaultKDFParamsSnapshot {
        VaultKDFParamsSnapshot(
            algorithm: .argon2id,
            memoryKiB: 65536,
            iterations: 2,
            parallelism: 2,
            saltLength: 16
        )
    }
}
