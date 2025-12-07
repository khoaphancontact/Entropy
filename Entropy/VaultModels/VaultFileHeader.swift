//
//  VaultFileHeader.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  VaultFileHeader.swift
//  EntropyVaultModels
//

import Foundation

/// Errors that can occur while decoding or validating a vault file header.
public enum VaultFileHeaderError: Error, Equatable {
    case emptyData
    case truncatedData
    case invalidMagic
    case unsupportedHeaderFormatVersion(UInt8)
    case malformedHeaderBody
    case unsupportedVaultVersion(UInt16)
    case invalidIntegrityHashLength(expected: Int, actual: Int)
}

/// Cryptographic method used to encrypt the vault payload.
public enum VaultEncryptionMethod: String, Codable, Sendable {
    case aes256GCM = "AES-256-GCM"
    // Future: case chacha20Poly1305, etc.
}

/// KDF snapshot used when the vault was created.
/// This is a *frozen* on-disk layout; do not change without migration.
public struct VaultKDFParamsSnapshot: Codable, Equatable, Sendable {
    
    public enum Algorithm: String, Codable, Sendable {
        case argon2id
        // Future: case scrypt, etc.
    }
    
    public let algorithm: Algorithm
    public let memoryKiB: Int
    public let iterations: Int
    public let parallelism: Int
    public let saltLength: Int
    
    public init(
        algorithm: Algorithm = .argon2id,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        saltLength: Int
    ) {
        self.algorithm = algorithm
        self.memoryKiB = memoryKiB
        self.iterations = iterations
        self.parallelism = parallelism
        self.saltLength = saltLength
    }
}

/// On-disk vault file header.
///
/// Disk layout (big-endian where applicable):
/// - 0..3:   Magic bytes "ENTR"
/// - 4:      headerFormatVersion (UInt8)
/// - 5..8:   headerLength (UInt32, number of bytes in JSON body)
/// - body:   JSON-encoded `VaultFileHeader`
///
/// The JSON body is strictly versioned and validated on load.
public struct VaultFileHeader: Codable, Equatable, Sendable {
    
    // MARK: - Disk constants
    
    public static let magic = "ENTR".data(using: .utf8)!  // 4 bytes
    public static let headerFormatVersion: UInt8 = 1      // format of the *header wrapper*
    
    /// Current vault file version (semantic versioning for vault format).
    /// Bump this when the *on-disk vault model* changes in a non-backward compatible way.
    public static let currentVaultVersion: UInt16 = 1
    
    /// Current schema version for the serialized inner model (VaultModelV1).
    public static let currentSchemaVersion: UInt16 = 1
    
    /// Expected integrity hash length (e.g. SHA-256 = 32 bytes).
    public static let integrityHashLength: Int = 32
    
    // MARK: - Header fields (JSON body)
    
    /// Version of the vault format.
    public let vaultVersion: UInt16
    
    /// Version of the inner schema representation.
    public let schemaVersion: UInt16
    
    /// When this vault file was originally created.
    public let createdAt: Date
    
    /// When this vault file was last modified.
    public let modifiedAt: Date
    
    /// Encryption method used for the vault payload.
    public let encryptionMethod: VaultEncryptionMethod
    
    /// KDF parameters used to derive the vault key at creation time.
    public let kdfParams: VaultKDFParamsSnapshot
    
    /// Integrity hash placeholder for the encrypted payload.
    ///
    /// This is typically the SHA-256 of the encrypted vault blob, computed
    /// by `VaultSerialization` and verified by `IntegrityChecks` before decrypt.
    public let integrityHash: Data
    
    // MARK: - Init
    
    public init(
        vaultVersion: UInt16 = Self.currentVaultVersion,
        schemaVersion: UInt16 = Self.currentSchemaVersion,
        createdAt: Date,
        modifiedAt: Date,
        encryptionMethod: VaultEncryptionMethod = .aes256GCM,
        kdfParams: VaultKDFParamsSnapshot,
        integrityHash: Data
    ) {
        self.vaultVersion = vaultVersion
        self.schemaVersion = schemaVersion
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.encryptionMethod = encryptionMethod
        self.kdfParams = kdfParams
        self.integrityHash = integrityHash
    }
    
    /// Convenience initializer for a brand new vault.
    /// Uses zeroed integrity hash; will be filled in by `VaultSerialization`.
    public static func newVaultHeader(
        now: Date = Date(),
        kdfParams: VaultKDFParamsSnapshot
    ) -> VaultFileHeader {
        let zeroHash = Data(repeating: 0, count: Self.integrityHashLength)
        return VaultFileHeader(
            vaultVersion: Self.currentVaultVersion,
            schemaVersion: Self.currentSchemaVersion,
            createdAt: now,
            modifiedAt: now,
            encryptionMethod: .aes256GCM,
            kdfParams: kdfParams,
            integrityHash: zeroHash
        )
    }
}

// MARK: - Validation

public extension VaultFileHeader {
    
    /// Validate invariants when loading from disk.
    ///
    /// - Throws: `VaultFileHeaderError` if the header is not acceptable.
    func validateOnLoad() throws {
        // Versioning: right now, we only accept exactly the current version.
        // When you add migrations, you can relax this to a range.
        guard vaultVersion == Self.currentVaultVersion else {
            throw VaultFileHeaderError.unsupportedVaultVersion(vaultVersion)
        }
        
        // Ensure integrity hash placeholder is the expected length.
        guard integrityHash.count == Self.integrityHashLength else {
            throw VaultFileHeaderError.invalidIntegrityHashLength(
                expected: Self.integrityHashLength,
                actual: integrityHash.count
            )
        }
    }
}

// MARK: - Encoding / Decoding to raw Data (header wrapper)

public extension VaultFileHeader {
    
    /// Encode the header to raw `Data` with magic + wrapper + JSON body.
    func encodeToData() throws -> Data {
        var data = Data()
        data.append(Self.magic)
        data.append(Self.headerFormatVersion)
        
        let encoder = JSONEncoder()
        // Stable encoding options can be tuned here if needed.
        let body = try encoder.encode(self)
        
        var length = UInt32(body.count).bigEndian
        data.append(Data(bytes: &length, count: MemoryLayout<UInt32>.size))
        data.append(body)
        
        return data
    }
    
    /// Decode a `VaultFileHeader` from raw `Data`.
    ///
    /// This performs:
    /// - structural checks (magic, header format version, length)
    /// - JSON decoding
    /// - semantic validation (`validateOnLoad`)
    static func decode(from data: Data) throws -> VaultFileHeader {
        guard !data.isEmpty else {
            throw VaultFileHeaderError.emptyData
        }
        
        let minimumSize = Self.magic.count + 1 + MemoryLayout<UInt32>.size
        guard data.count >= minimumSize else {
            throw VaultFileHeaderError.truncatedData
        }
        
        var offset = 0
        
        // Magic
        let magicSlice = data[offset..<offset + Self.magic.count]
        guard magicSlice == Self.magic[0..<Self.magic.count] else {
            throw VaultFileHeaderError.invalidMagic
        }
        offset += Self.magic.count
        
        // Header format version
        let headerVersion = data[offset]
        guard headerVersion == Self.headerFormatVersion else {
            throw VaultFileHeaderError.unsupportedHeaderFormatVersion(headerVersion)
        }
        offset += 1
        
        // Header length
        let lengthRange = offset ..< (offset + MemoryLayout<UInt32>.size)
        let lengthData = data[lengthRange]
        let lengthValue: UInt32 = lengthData.withUnsafeBytes { raw in
            let b = raw.bindMemory(to: UInt8.self)
            return (UInt32(b[0]) << 24) |
                   (UInt32(b[1]) << 16) |
                   (UInt32(b[2]) << 8)  |
                    UInt32(b[3])
        }
        offset += MemoryLayout<UInt32>.size
        
        guard lengthValue > 0 else {
            throw VaultFileHeaderError.truncatedData
        }
        
        let expectedEnd = offset + Int(lengthValue)
        guard expectedEnd <= data.count else {
            throw VaultFileHeaderError.truncatedData
        }
        
        let bodyData = data[offset..<expectedEnd]
        
        let decoder = JSONDecoder()
        let header: VaultFileHeader
        do {
            header = try decoder.decode(VaultFileHeader.self, from: bodyData)
        } catch {
            throw VaultFileHeaderError.malformedHeaderBody
        }
        
        try header.validateOnLoad()
        return header
    }
}
