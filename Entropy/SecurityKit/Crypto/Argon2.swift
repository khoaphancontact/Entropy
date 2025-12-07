//
//  Argon2.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/5/25.
//

//
//  High-level Argon2id wrapper for password-based key derivation.
//  Uses the Argon2 C library via CArgon2 module.
//
//  This file assumes you have:
//  - Added the Argon2 C library (phc-winner-argon2) to your project
//  - Exposed it as a Swift module named `CArgon2`
//  - Have `argon2.h` available with `argon2id_hash_raw` symbol
//

import Foundation
import CArgon2   // <- If your module is named differently, change this line.

public struct Argon2Params: Equatable, Sendable {
    /// Memory cost in KiB (e.g. 64_000 to 128_000).
    public let memoryKiB: Int
    /// Time cost (number of iterations, e.g. 2 to 3).
    public let iterations: Int
    /// Degree of parallelism (e.g. 2 to 4).
    public let parallelism: Int
    /// Salt length in bytes (typically 16 to 32).
    public let saltLength: Int
    /// Output key length in bytes (for master key, 32).
    public let outputLength: Int

    public init(
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        saltLength: Int = 16,
        outputLength: Int = 32
    ) {
        self.memoryKiB = memoryKiB
        self.iterations = iterations
        self.parallelism = parallelism
        self.saltLength = saltLength
        self.outputLength = outputLength
    }
}

public enum Argon2Error: Error {
    case invalidParams
    case invalidSaltLength
    case derivationFailed(code: Int32)
}

/// High-level Argon2id wrapper.
/// - Provides two main APIs:
///   - derive(password:params:) -> (key, salt)
///   - derive(password:salt:params:) -> key
public enum Argon2 {

    /// Derive a key using a fresh random salt.
    /// - Returns: (derived key, random salt)
    public static func derive(password: Data, params: Argon2Params) throws -> (key: Data, salt: Data) {
        try validate(params: params)
        let salt = try SecureRandom.bytes(count: params.saltLength)
        let key = try derive(password: password, salt: salt, params: params)
        return (key, salt)
    }

    /// Derive a key using a provided salt (for verify/unlock).
    public static func derive(password: Data, salt: Data, params: Argon2Params) throws -> Data {
        try validate(params: params)
        guard salt.count == params.saltLength else {
            throw Argon2Error.invalidSaltLength
        }
        return try argon2id(password: password, salt: salt, params: params)
    }

    // MARK: - Internal validation

    private static func validate(params: Argon2Params) throws {
        // Conservative bounds that match the Step 1 security guide.
        let memoryOK = params.memoryKiB >= 32_768   // 32 MiB minimum; recommended 64–128 MiB
        let itersOK  = params.iterations >= 1
        let parOK    = params.parallelism >= 1
        let saltOK   = (16...32).contains(params.saltLength)
        let outOK    = params.outputLength == 32    // We expect 32-byte master keys

        guard memoryOK, itersOK, parOK, saltOK, outOK else {
            throw Argon2Error.invalidParams
        }
    }

    // MARK: - Argon2id core

    private static func argon2id(password: Data, salt: Data, params: Argon2Params) throws -> Data {
        var output = Data(count: params.outputLength)

        let result: Int32 = output.withUnsafeMutableBytes { outPtr in
            let outBuf = outPtr.bindMemory(to: UInt8.self).baseAddress!

            return password.withUnsafeBytes { pwPtr in
                let pwBuf = pwPtr.bindMemory(to: UInt8.self).baseAddress!

                return salt.withUnsafeBytes { saltPtr in
                    let saltBuf = saltPtr.bindMemory(to: UInt8.self).baseAddress!

                    return argon2idHashRaw(
                        iterations: UInt32(params.iterations),
                        memoryKiB: UInt32(params.memoryKiB),
                        parallelism: UInt32(params.parallelism),
                        password: pwBuf, passwordLen: password.count,
                        salt: saltBuf, saltLen: salt.count,
                        output: outBuf, outputLen: output.count
                    )
                }
            }
        }

        guard result == ARGON2_OK else {
            throw Argon2Error.derivationFailed(code: result)
        }

        return output
    }
}

// MARK: - Argon2 C binding

/// Thin wrapper around the C Argon2id function.
/// Expects:
/// - iterations: time cost
/// - memoryKiB: memory cost in KiB
/// - parallelism: lanes
/// - password: raw pointer to password bytes
/// - salt: raw pointer to salt bytes
/// - output: raw pointer to output buffer (already allocated)
///
/// Returns:
/// - 0 (ARGON2_OK) on success
/// - non-zero error code on failure
@inline(__always)
private func argon2idHashRaw(
    iterations: UInt32,
    memoryKiB: UInt32,
    parallelism: UInt32,
    password: UnsafeRawPointer, passwordLen: Int,
    salt: UnsafeRawPointer, saltLen: Int,
    output: UnsafeMutableRawPointer, outputLen: Int
) -> Int32 {
    // Crypto parameters from our wrapper are already validated.
    // We just forward to the C API and let it return a status code.
    let result = argon2id_hash_raw(
        iterations,
        memoryKiB,
        parallelism,
        password,
        passwordLen,
        salt,
        saltLen,
        output,
        outputLen
    )
    return result
}
