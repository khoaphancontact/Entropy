//
//  FastUnlockKeyManager.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//
//  Manages a short-lived “fast unlock key” that allows skipping Argon2
//  while still enforcing strong device-based security. Uses:
//  - Secure Enclave if available
//  - Otherwise Keychain with `.whenUnlocked`
//  - KDFCachePolicy to determine expiry
//
//  The fast unlock key NEVER leaves Secure Enclave/Keychain unencrypted.
//  When retrieved, it is always immediately wrapped in ZeroizedData.
//  When expired, it is destroyed.
//

import Foundation
import CryptoKit
import LocalAuthentication

public enum FastUnlockKeyError: Error, Equatable {
    case keyNotAvailable
    case policyExpired
    case storageFailure
    case retrievalFailure
    case invalidKey

    // Milestone K — Secure Enclave API scaffolding
    case notImplemented
    case enclaveUnavailable
    case encryptionFailure
    case decryptionFailure
}

/// Stores the ephemeral cached key + cache policy.
private struct CachedFastKey: Sendable {
    let key: ZeroizedData
    var state: KDFCacheState
}

/// Actor that manages the fast-unlock key lifecycle.
public actor FastUnlockKeyManager {

    // MARK: - Keychain constants

    private let keychainAccount = "com.entropy.fastunlock.key"
    private let keychainService = "Entropy"

    // MARK: - Internal State

    private var cached: CachedFastKey? = nil

    public init() {}

    // MARK: - Public API

    /// Returns true if there is a cached fast unlock key that has not expired.
    public func hasValidKey(at date: Date = Date()) -> Bool {
        guard let cached else { return false }
        return cached.state.policy.allowsCaching && !cached.state.isExpired(at: date)
    }

    /// Retrieves the fast unlock key if valid.
    /// Otherwise returns `nil`.
    public func getKey(at date: Date = Date()) -> ZeroizedData? {
        guard let cached else { return nil }
        guard !cached.state.isExpired(at: date) else {
            Task {
                do {
                    try await invalidateKey()
                } catch {
                    print("FastUnlockKeyManager: failed to invalidate key: \(error)")
                }
            }
            return nil
        }
        return cached.key
    }

    /// Creates a new fast-unlock key and stores it using the provided policy.
    @discardableResult
    public func generateAndStoreFastUnlockKey(
        policy: KDFCachePolicy
    ) throws -> ZeroizedData {

        guard policy.allowsCaching else {
            try invalidateKey()
            throw FastUnlockKeyError.policyExpired
        }

        // Step 1: Generate a fresh 32-byte secret
        let raw = try SecureRandom.bytes(count: 32)
        let key = ZeroizedData(copying: raw)

        // Step 2: Store securely in Keychain
        try storeKeychainProtectedKey(raw)

        // Step 3: Store in RAM with policy
        let state = KDFCacheState(policy: policy, createdAt: Date())
        cached = CachedFastKey(key: key, state: state)

        return key
    }

    /// Attempts to load the fast unlock key from secure storage.
    public func reloadFromSecureStorage(
        at date: Date = Date()
    ) throws -> ZeroizedData {

        guard let cached else {
            throw FastUnlockKeyError.keyNotAvailable
        }

        guard !cached.state.isExpired(at: date) else {
            try invalidateKey()
            throw FastUnlockKeyError.policyExpired
        }

        let raw = try loadKeychainProtectedKey()
        return ZeroizedData(copying: raw)
    }

    /// Updates lifecycle flags based on app background/device lock events.
    public func updateLifecycle(
        appDidBackground: Bool? = nil,
        deviceDidLock: Bool? = nil,
        at date: Date = Date()
    ) async {

        guard var cached else { return }
        cached.state = cached.state.withLifecycleUpdate(
            appBackgrounded: appDidBackground,
            deviceLocked: deviceDidLock
        )

        self.cached = cached

        // If expired because of lifecycle changes, wipe it
        if cached.state.isExpired(at: date) {
            try? invalidateKey()
        }
    }

    /// Destroys all fast-unlock material immediately.
    public func invalidateKey() throws {
        cached = nil
        try deleteKeychainProtectedKey()
    }

    // MARK: - Keychain Storage (Secure Enclave fallback)

    private func storeKeychainProtectedKey(_ rawKey: Data) throws {
        // Remove old value
        try? deleteKeychainProtectedKey()

        let query: [String : Any] = [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrAccount as String:       keychainAccount,
            kSecAttrService as String:       keychainService,
            kSecAttrAccessible as String:    kSecAttrAccessibleWhenUnlocked,
            kSecValueData as String:         rawKey
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw FastUnlockKeyError.storageFailure
        }
    }

    private func loadKeychainProtectedKey() throws -> Data {
        let query: [String : Any] = [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrAccount as String:       keychainAccount,
            kSecAttrService as String:       keychainService,
            kSecReturnData as String:        true,
            kSecMatchLimit as String:        kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess, let data = item as? Data else {
            throw FastUnlockKeyError.retrievalFailure
        }

        return data
    }

    private func deleteKeychainProtectedKey() throws {
        let query: [String : Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrService as String: keychainService
        ]

        SecItemDelete(query as CFDictionary)
    }

    // MARK: - SECURE ENCLAVE API (Milestone K)
    // These are stubs for now; real implementations arrive in Step 2–3.

    /// Generate a Secure Enclave–backed keypair (stub).
    public func generateSecureEnclaveKeypair() throws -> Data {
        throw FastUnlockKeyError.notImplemented
    }

    /// Encrypt the vaultKey using the Secure Enclave public key (stub).
    public func encryptVaultKeyWithEnclavePublicKey(
        _ vaultKey: ZeroizedData
    ) throws -> Data {
        throw FastUnlockKeyError.notImplemented
    }

    /// Decrypt the vaultKey using Secure Enclave private key + biometrics (stub).
    public func decryptVaultKeyWithSecureEnclave(
        _ encryptedKey: Data
    ) async throws -> ZeroizedData {
        throw FastUnlockKeyError.notImplemented
    }

    /// Invalidate Secure Enclave–backed key material (stub).
    public func invalidateEnclaveKeys() throws {
        throw FastUnlockKeyError.notImplemented
    }
}
