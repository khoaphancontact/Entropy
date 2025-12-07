//
//  IntegrityChecks.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/5/25.
//

//
//  IntegrityChecks.swift
//  SecurityKit
//
//  Centralized integrity & structure validation utilities for Entropy.
//
//  Responsibilities:
//  - Validate Argon2 parameter structures loaded from disk
//  - Validate vault key bundles (VaultKeyBundleV1)
//  - Validate per-entry ciphertext bundles (VaultCiphertext)
//  - Provide SHA-256 hashing and HMAC-SHA256 helpers with constant-time verify
//

import Foundation
import CryptoKit

// MARK: - Errors

public enum IntegrityError: Error, Equatable {
    case invalidArgon2Params
    case invalidVaultKeyBundle
    case invalidCiphertextBundle
    case invalidMAC
    case invalidInput
}

// MARK: - IntegrityChecks

public enum IntegrityChecks {

    // These mirror AES-GCM expectations used elsewhere (AESGCM, VaultEncryption, VaultKeyDerivation).
    private static let aeadNonceLength = 12
    private static let gcmTagLength = 16

    // These mirror Argon2 security policy constraints.
    private static let minArgon2MemoryKiB = 32_768
    private static let minArgon2Iterations = 1
    private static let minArgon2Parallelism = 1
    private static let minArgon2SaltLength = 16
    private static let maxArgon2SaltLength = 32
    private static let argon2OutputLength = 32

    // MARK: - Argon2 Parameter Validation

    /// Validates Argon2 parameters loaded from disk before using them.
    /// Mirrors the logic in Argon2.validate(params:), but exposed at the SecurityKit level.
    @discardableResult
    public static func validateArgon2Params(_ params: Argon2Params) throws -> Argon2Params {
        let memoryOK = params.memoryKiB >= minArgon2MemoryKiB
        let itersOK  = params.iterations >= minArgon2Iterations
        let parOK    = params.parallelism >= minArgon2Parallelism
        let saltOK   = (minArgon2SaltLength...maxArgon2SaltLength).contains(params.saltLength)
        let outOK    = params.outputLength == argon2OutputLength

        guard memoryOK, itersOK, parOK, saltOK, outOK else {
            throw IntegrityError.invalidArgon2Params
        }

        return params
    }

    // MARK: - VaultKeyBundleV1 Validation

    /// Validates a VaultKeyBundleV1 before attempting expensive KDF and AES operations.
    ///
    /// Checks:
    /// - Argon2 params within policy
    /// - Salt length matches Argon2Params.saltLength and is in 16...32
    /// - Nonce length == 12 bytes
    /// - Ciphertext length >= 16 bytes (AES-GCM tag size)
    @discardableResult
    public static func validateVaultKeyBundle(_ bundle: VaultKeyBundleV1) throws -> VaultKeyBundleV1 {
        try validateArgon2Params(bundle.kdfParams)

        // Salt must match Argon2Params.saltLength and be within allowed range.
        let saltCount = bundle.salt.count
        guard saltCount == bundle.kdfParams.saltLength,
              (minArgon2SaltLength...maxArgon2SaltLength).contains(saltCount) else {
            throw IntegrityError.invalidVaultKeyBundle
        }

        // Nonce and ciphertext structural checks (AES-GCM).
        guard bundle.vaultKeyNonce.count == aeadNonceLength else {
            throw IntegrityError.invalidVaultKeyBundle
        }

        guard bundle.vaultKeyCiphertext.count >= gcmTagLength else {
            throw IntegrityError.invalidVaultKeyBundle
        }

        return bundle
    }

    // MARK: - VaultCiphertext Validation

    /// Validates a VaultCiphertext bundle (per-entry encryption) before decrypting.
    ///
    /// Checks:
    /// - Nonce length == 12 bytes
    /// - Ciphertext length >= 16 bytes (tag size)
    @discardableResult
    public static func validateVaultCiphertext(_ ciphertext: VaultCiphertext) throws -> VaultCiphertext {
        guard ciphertext.nonce.count == aeadNonceLength else {
            throw IntegrityError.invalidCiphertextBundle
        }

        guard ciphertext.ciphertext.count >= gcmTagLength else {
            throw IntegrityError.invalidCiphertextBundle
        }

        return ciphertext
    }

    // MARK: - SHA-256 Helpers

    /// Computes a SHA-256 hash over the given data. Suitable for vault-level checksums.
    public static func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    /// Verifies that `expectedHash` equals SHA-256(data), using constant-time comparison.
    public static func verifySHA256(data: Data, expectedHash: Data) -> Bool {
        let actual = sha256(data)
        return SecureCompare.equal(actual, expectedHash)  // constant-time compare
    }

    // MARK: - HMAC-SHA256 (MAC) Helpers

    /// Computes HMAC-SHA256 over `data` using a key stored in ZeroizedData.
    /// The returned MAC is NOT zeroized (MACs are not secret).
    public static func hmacSHA256(key: ZeroizedData, data: Data) throws -> Data {
        // Extract key bytes once, then zero the copy.
        var keyCopy: Data
        do {
            keyCopy = try key.withBytes { Data($0) }   // ZeroizedData access
        } catch {
            throw IntegrityError.invalidInput
        }
        defer {
            keyCopy.resetBytes(in: 0..<keyCopy.count)
        }

        let symmetricKey = SymmetricKey(data: keyCopy)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }

    /// Verifies an HMAC-SHA256 over `data` using a ZeroizedData key and constant-time comparison.
    ///
    /// - Returns: true if MAC is valid, false otherwise.
    public static func verifyHMACSHA256(
        key: ZeroizedData,
        data: Data,
        expectedMAC: Data
    ) throws -> Bool {
        let actualMAC = try hmacSHA256(key: key, data: data)
        return SecureCompare.equal(actualMAC, expectedMAC)
    }

    // MARK: - High-Level Vault Helpers (for future use)

    /// Computes a vault-level integrity hash (SHA-256) for the entire serialized vault blob.
    ///
    /// This does NOT provide authenticity (no key), only integrity/corruption detection.
    public static func computeVaultBlobHash(_ blob: Data) -> Data {
        return sha256(blob)
    }

    /// Verifies that a serialized vault blob matches its stored SHA-256 hash.
    public static func verifyVaultBlobHash(_ blob: Data, expectedHash: Data) -> Bool {
        return verifySHA256(data: blob, expectedHash: expectedHash)
    }
}
