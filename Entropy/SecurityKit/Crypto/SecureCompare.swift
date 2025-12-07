//
//  SecureCompare.swift
//  SecurityKit
//
//  Constant-time equality for secret values. Avoids early exits and branching on data.
//

import Foundation

public enum SecureCompare {

    /// Constant-time comparison of two Data values.
    /// - Returns: true if equal, false otherwise.
    /// - Important: Uses raw memory access to avoid Data-index overhead.
    public static func equal(_ a: Data, _ b: Data) -> Bool {
        var diff: UInt8 = UInt8(truncatingIfNeeded: a.count ^ b.count)

        a.withUnsafeBytes { ap in
            b.withUnsafeBytes { bp in
                let ac = ap.count
                let bc = bp.count
                let count = max(ac, bc)

                for i in 0..<count {
                    let av = i < ac ? ap[i] : 0
                    let bv = i < bc ? bp[i] : 0
                    diff |= av ^ bv
                }
            }
        }

        return diff == 0
    }

    /// Constant-time comparison of two raw byte buffers.
    /// - Returns: true if equal, false otherwise.
    public static func equal(_ a: UnsafeRawBufferPointer, _ b: UnsafeRawBufferPointer) -> Bool {
        var diff: UInt8 = UInt8(truncatingIfNeeded: a.count ^ b.count)
        let count = max(a.count, b.count)

        for i in 0..<count {
            let av = i < a.count ? a[i] : 0
            let bv = i < b.count ? b[i] : 0
            diff |= av ^ bv
        }

        return diff == 0
    }
}
