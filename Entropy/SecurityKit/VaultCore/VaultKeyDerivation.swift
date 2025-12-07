import Foundation

// MARK: - Argon2Params Codable (needed because VaultKeyBundleV1 is Codable)

extension Argon2Params: Codable {
    enum CodingKeys: String, CodingKey {
        case memoryKiB
        case iterations
        case parallelism
        case saltLength
        case outputLength
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let memoryKiB = try c.decode(Int.self, forKey: .memoryKiB)
        let iterations = try c.decode(Int.self, forKey: .iterations)
        let parallelism = try c.decode(Int.self, forKey: .parallelism)
        let saltLength = try c.decode(Int.self, forKey: .saltLength)
        let outputLength = try c.decode(Int.self, forKey: .outputLength)

        self.init(
            memoryKiB: memoryKiB,
            iterations: iterations,
            parallelism: parallelism,
            saltLength: saltLength,
            outputLength: outputLength
        )
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(memoryKiB, forKey: .memoryKiB)
        try c.encode(iterations, forKey: .iterations)
        try c.encode(parallelism, forKey: .parallelism)
        try c.encode(saltLength, forKey: .saltLength)
        try c.encode(outputLength, forKey: .outputLength)
    }
}

// MARK: - VaultKeyBundleV1

/// Version 1 vault key bundle.
/// Stores everything needed to re-derive the master key and decrypt the vault key.
public struct VaultKeyBundleV1: Codable, Equatable {
    /// Argon2 parameters used for master key derivation.
    public let kdfParams: Argon2Params

    /// Salt used with Argon2.
    public let salt: Data

    /// AES-GCM ciphertext || tag of the vault key.
    public let vaultKeyCiphertext: Data

    /// AES-GCM nonce (12 bytes).
    public let vaultKeyNonce: Data

    public init(
        kdfParams: Argon2Params,
        salt: Data,
        vaultKeyCiphertext: Data,
        vaultKeyNonce: Data
    ) {
        self.kdfParams = kdfParams
        self.salt = salt
        self.vaultKeyCiphertext = vaultKeyCiphertext
        self.vaultKeyNonce = vaultKeyNonce
    }
}

// MARK: - Errors

public enum VaultKeyDerivationError: Error, Equatable {
    case invalidPassword
    case invalidKDFParams
    case randomFailure
    case encryptionFailure
    case decryptionFailure
}

// MARK: - VaultKeyDerivation

public enum VaultKeyDerivation {

    /// Minimum password length (bytes).
    public static var minimumPasswordLength: Int = 8

    private static let expectedNonceLength = 12
    private static let minimumCiphertextLength = 16 // at least GCM tag

    // MARK: - Helpers

    /// Overwrite a Data buffer with zeros.
    @inline(__always)
    private static func zeroize(_ data: inout Data) {
        guard !data.isEmpty else { return }
        data.resetBytes(in: 0..<data.count)
    }

    // MARK: - Create Bundle (V1)

    /// Creates a new V1 vault key bundle from a password.
    ///
    /// - Returns: (bundle, vaultKey) where `vaultKey` is wrapped in `ZeroizedData`.
    public static func createBundleV1(
        password: Data,
        params: Argon2Params
    ) throws -> (bundle: VaultKeyBundleV1, vaultKey: ZeroizedData) {

        // 1) Password policy
        guard password.count >= minimumPasswordLength else {
            throw VaultKeyDerivationError.invalidPassword
        }

        // 2) Enforce 32-byte output
        var kdfParams = params
        if kdfParams.outputLength != 32 {
            kdfParams = Argon2Params(
                memoryKiB: params.memoryKiB,
                iterations: params.iterations,
                parallelism: params.parallelism,
                saltLength: params.saltLength,
                outputLength: 32
            )
        }

        // 3) Derive master key + salt
        var masterKey: Data
        let salt: Data
        do {
            let derived = try Argon2.derive(password: password, params: kdfParams)
            masterKey = derived.key
            salt = derived.salt
        } catch let e as Argon2Error {
            // This covers invalid params / internal Argon2 failure
            switch e {
            case .invalidParams:
                throw VaultKeyDerivationError.invalidKDFParams
            default:
                throw VaultKeyDerivationError.invalidKDFParams
            }
        } catch {
            throw VaultKeyDerivationError.invalidKDFParams
        }
        defer { zeroize(&masterKey) }

        // 4) Generate random 32-byte vault key
        var vaultKeyData: Data
        do {
            vaultKeyData = try SecureRandom.bytes(count: 32)
        } catch {
            throw VaultKeyDerivationError.randomFailure
        }
        defer { zeroize(&vaultKeyData) }

        // 5) Encrypt vault key with AES-GCM (CryptoKit wrapper)
        let sealed: AESGCM.SealedBox
        do {
            sealed = try AESGCM.encrypt(plaintext: vaultKeyData, using: masterKey)
        } catch {
            throw VaultKeyDerivationError.encryptionFailure
        }

        // Sanity check nonce/ciphertext lengths to match AESGCM expectations. :contentReference[oaicite:2]{index=2}
        guard sealed.nonce.count == expectedNonceLength,
              sealed.ciphertext.count >= minimumCiphertextLength else {
            throw VaultKeyDerivationError.encryptionFailure
        }

        // 6) Build bundle
        let bundle = VaultKeyBundleV1(
            kdfParams: kdfParams,
            salt: salt,
            vaultKeyCiphertext: sealed.ciphertext,
            vaultKeyNonce: sealed.nonce
        )

        // 7) Wrap vault key in ZeroizedData for caller; Data copy will be zeroized by defer
        let zeroizedVaultKey = ZeroizedData(copying: vaultKeyData) // matches your API :contentReference[oaicite:3]{index=3}

        return (bundle, zeroizedVaultKey)
    }

    // MARK: - Decrypt Bundle (V1)

    /// Decrypts a V1 vault key bundle using the provided password.
    public static func decryptVaultKeyV1(
        from bundle: VaultKeyBundleV1,
        password: Data
    ) throws -> ZeroizedData {

        // 1) Password policy
        guard password.count >= minimumPasswordLength else {
            throw VaultKeyDerivationError.invalidPassword
        }

        // 2) Quick structural checks to avoid pointless Argon2 work
        guard bundle.vaultKeyNonce.count == expectedNonceLength,
              bundle.vaultKeyCiphertext.count >= minimumCiphertextLength else {
            throw VaultKeyDerivationError.decryptionFailure
        }

        // 3) Enforce 32-byte output
        var kdfParams = bundle.kdfParams
        if kdfParams.outputLength != 32 {
            kdfParams = Argon2Params(
                memoryKiB: bundle.kdfParams.memoryKiB,
                iterations: bundle.kdfParams.iterations,
                parallelism: bundle.kdfParams.parallelism,
                saltLength: bundle.kdfParams.saltLength,
                outputLength: 32
            )
        }

        // 4) Derive master key using stored salt
        var masterKey: Data
        do {
            masterKey = try Argon2.derive(
                password: password,
                salt: bundle.salt,
                params: kdfParams
            )
        } catch let e as Argon2Error {
            switch e {
            case .invalidParams:
                throw VaultKeyDerivationError.invalidKDFParams
            default:
                throw VaultKeyDerivationError.decryptionFailure
            }
        } catch {
            throw VaultKeyDerivationError.decryptionFailure
        }
        defer { zeroize(&masterKey) }

        // 5) Rebuild sealed box and decrypt
        let sealed = AESGCM.SealedBox(
            ciphertext: bundle.vaultKeyCiphertext,
            nonce: bundle.vaultKeyNonce
        )

        var decryptedVaultKey: Data
        do {
            decryptedVaultKey = try AESGCM.decrypt(sealed, using: masterKey)
        } catch {
            throw VaultKeyDerivationError.decryptionFailure
        }
        defer { zeroize(&decryptedVaultKey) }

        // 6) Wrap in ZeroizedData for caller
        return ZeroizedData(copying: decryptedVaultKey)
    }
}
