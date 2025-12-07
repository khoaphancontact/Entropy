//
//  Argon2.swift
//  Entropy
//
//  High-level Argon2id wrapper for password-based key derivation.
//  Uses the Argon2 C library via a bridging header.
//
//  Requirements:
//  - Add Argon2 C library sources (from PHC winner repo) to the project
//  - Add argon2.h to bridging header
//  - Ensure argon2id_hash_raw(...) is visible from Swift
//  - Ensure Argon2_ErrorCodes is bridged as an enum from argon2.h
//

import Foundation

// MARK: - Public Parameter Structure

public struct Argon2Params: Equatable, Sendable {
    /// Memory cost in KiB (e.g. 64_000 to 128_000).
    public let memoryKiB: Int
    /// Time cost (iterations).
    public let iterations: Int
    /// Degree of parallelism (threads).
    public let parallelism: Int
    /// Salt length in bytes (typically 16 to 32).
    public let saltLength: Int
    /// Output key length in bytes (normally 32 for a master key).
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

// MARK: - Error Definitions

public enum Argon2Error: Error, Equatable {
    case invalidParams
    case invalidSaltLength
    case derivationFailed(code: Int32)
}

// MARK: - Main Wrapper API

public enum Argon2 {

    /// Derive a key using a randomly generated salt.
    public static func derive(password: Data, params: Argon2Params) throws -> (key: Data, salt: Data) {
        try validate(params: params)
        let salt = try SecureRandom.bytes(count: params.saltLength)
        let key = try derive(password: password, salt: salt, params: params)
        return (key, salt)
    }

    /// Derive a key using an existing salt (for unlocking a vault).
    public static func derive(password: Data, salt: Data, params: Argon2Params) throws -> Data {
        try validate(params: params)
        guard salt.count == params.saltLength else {
            throw Argon2Error.invalidSaltLength
        }
        return try argon2id(password: password, salt: salt, params: params)
    }

    // MARK: - Parameter validation

    private static func validate(params: Argon2Params) throws {
        // Matches Step 1 guidelines
        let memoryOK = params.memoryKiB >= 32_768        // 32 MiB minimum
        let itersOK  = params.iterations >= 1
        let parOK    = params.parallelism >= 1
        let saltOK   = (16...32).contains(params.saltLength)
        let outOK    = params.outputLength == 32          // we expect a 32-byte master key

        guard memoryOK, itersOK, parOK, saltOK, outOK else {
            throw Argon2Error.invalidParams
        }
    }

    // MARK: - Actual Argon2id Worker

    private static func argon2id(password: Data, salt: Data, params: Argon2Params) throws -> Data {
        let outputLength = params.outputLength

        // Allocate secure output buffer
        let outPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: outputLength)
        defer { outPtr.deallocate() }

        // Call Argon2 through bridging header
        let result: Argon2_ErrorCodes = password.withUnsafeBytes { pwPtr in
            guard let pwBuf = pwPtr.baseAddress else { return ARGON2_PWD_TOO_SHORT }

            return salt.withUnsafeBytes { saltPtr in
                guard let saltBuf = saltPtr.baseAddress else { return ARGON2_SALT_TOO_SHORT }

                return argon2idHashRaw(
                    iterations: UInt32(params.iterations),
                    memoryKiB: UInt32(params.memoryKiB),
                    parallelism: UInt32(params.parallelism),
                    password: pwBuf, passwordLen: password.count,
                    salt: saltBuf, saltLen: salt.count,
                    output: UnsafeMutableRawPointer(outPtr), outputLen: outputLength
                )
            }
        }

        // Validate return code
        guard result == ARGON2_OK else {
            throw Argon2Error.derivationFailed(code: Int32(result.rawValue))
        }

        // Copy derived key into Swift Data
        return Data(bytes: outPtr, count: outputLength)
    }
}

// MARK: - C Binding

/// Thin wrapper around argon2id_hash_raw from argon2.h via bridging header.
@inline(__always)
private func argon2idHashRaw(
    iterations: UInt32,
    memoryKiB: UInt32,
    parallelism: UInt32,
    password: UnsafeRawPointer, passwordLen: Int,
    salt: UnsafeRawPointer, saltLen: Int,
    output: UnsafeMutableRawPointer, outputLen: Int
) -> Argon2_ErrorCodes {
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

    // Map numeric return code into Argon2_ErrorCodes enum
    return Argon2_ErrorCodes(rawValue: result) ?? ARGON2_OK
}

