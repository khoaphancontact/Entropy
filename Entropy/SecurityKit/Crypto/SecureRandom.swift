//  SecureRandom.swift
//  SecurityKit
//
//  Cryptographically secure randomness provider for salts, nonces, keys, and OTP seeds.
//  Fails loudly if randomness cannot be gathered. No deterministic PRNG, no internal state.

import Foundation
import Security

public enum SecureRandomError: Error, Equatable {
    case negativeLength
    case entropyUnavailable(status: OSStatus)
}

public struct SecureRandom {
    private init() {}

    /// Returns `count` cryptographically secure random bytes.
    /// - Throws: `SecureRandomError.entropyUnavailable` if no system entropy is available.
    ///           `SecureRandomError.negativeLength` if count is negative.
    public static func bytes(count: Int) throws -> Data {
        if count < 0 {
            throw SecureRandomError.negativeLength
        }
        if count == 0 {
            return Data()
        }

        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { rawBuf -> OSStatus in
            guard let base = rawBuf.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }

        guard status == errSecSuccess else {
            throw SecureRandomError.entropyUnavailable(status: status)
        }

        return data
    }

    /// Fills the provided raw buffer with cryptographically secure random bytes.
    /// Throws if entropy cannot be gathered.
    public static func fill(_ buffer: UnsafeMutableRawBufferPointer) throws {
        guard buffer.count > 0 else { return }
        guard let base = buffer.baseAddress else { return }

        let status = SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
        guard status == errSecSuccess else {
            throw SecureRandomError.entropyUnavailable(status: status)
        }
    }

    /// Returns a random 64-bit unsigned integer.
    /// Generates 8 bytes of secure random data and interprets
    /// them as a little-endian UInt64.
    public static func uint64() throws -> UInt64 {
        var value: UInt64 = 0

        try withUnsafeMutableBytes(of: &value) { rawBuf in
            try SecureRandom.fill(rawBuf)
        }

        return UInt64(littleEndian: value)
    }
}
