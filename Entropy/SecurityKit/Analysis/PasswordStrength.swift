//
//  PasswordStrength.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  PasswordStrength.swift
//  Entropy
//
//  Scaffolding for password complexity scoring (Milestone M).
//  This does NOT yet implement real scoring logic.
//  It defines the API that Vault Models and UI will rely on.
//

import Foundation

/// Coarse-grained strength categories for a password.
/// Intended to drive UI, security score badges, and recommendations.
public enum PasswordStrength: Int, Codable, Equatable, Sendable {
    case dangerous = 0   // trivially guessable / reused / extremely weak
    case low        = 1  // weak, but not completely trivial
    case medium     = 2  // acceptable but could be improved
    case high       = 3  // strong by modern standards
}

/// Errors that can be thrown by the password strength evaluator.
public enum PasswordStrengthError: Error, Equatable, Sendable {
    /// The evaluator has not been implemented yet.
    case notImplemented
}

/// Result object for password strength evaluation.
/// This is intentionally future-proofed to support richer analysis once
/// you implement real scoring logic.
public struct PasswordStrengthResult: Codable, Equatable, Sendable {
    /// The coarse strength bucket.
    public let strength: PasswordStrength

    /// Optional normalized score (0–100). `nil` until implemented.
    public let score: Int?

    /// Measured or estimated entropy in bits. `nil` until implemented.
    public let estimatedEntropyBits: Double?

    /// Raw length of the password (in Unicode scalar count or bytes; TBD).
    public let length: Int?

    public init(
        strength: PasswordStrength,
        score: Int? = nil,
        estimatedEntropyBits: Double? = nil,
        length: Int? = nil
    ) {
        self.strength = strength
        self.score = score
        self.estimatedEntropyBits = estimatedEntropyBits
        self.length = length
    }
}

/// Evaluates the strength of a password contained in a ZeroizedData instance.
///
/// IMPORTANT (Milestone M):
/// - This is API scaffolding only.
/// - The implementation currently throws `.notImplemented`.
/// - Real scoring logic will be added in Step 2 when Vault models exist.
public enum PasswordStrengthEvaluator {

    /// Evaluate the strength of a password.
    ///
    /// - Parameter password: The password wrapped in `ZeroizedData`.
    /// - Returns: A `PasswordStrengthResult` describing computed strength.
    /// - Throws: `PasswordStrengthError.notImplemented` for now.
    public static func evaluate(
        _ password: ZeroizedData
    ) throws -> PasswordStrengthResult {
        // In Step 2, this will:
        // - Access the password via password.withBytes { ... }
        // - Interpret bytes as UTF-8 / scalar sequence
        // - Compute length, character classes, entropy estimates
        // - Derive PasswordStrength + score (0–100)
        throw PasswordStrengthError.notImplemented
    }

    /// Convenience utility for callers that only care about the bucket.
    ///
    /// - Returns: `PasswordStrength`
    /// - Throws: `PasswordStrengthError.notImplemented` for now.
    public static func strengthOnly(
        _ password: ZeroizedData
    ) throws -> PasswordStrength {
        let result = try evaluate(password)
        return result.strength
    }
}
