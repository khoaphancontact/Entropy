//
//  ZeroizedData.swift
//  Entropy
//
//  Secure container for sensitive bytes that zeroizes memory on wipe/deinit.
//  Updated with ZeroizePolicy for Milestone J.
//

import Foundation

// MARK: - Policies

/// Defines how and when internal memory should be wiped.
public enum ZeroizePolicy: Sendable, Equatable {
    case onDeinit          // Wipe on deinit (default)
    case afterRead         // Wipe immediately after first read
    case manual            // Caller controls lifetime; deinit does NOT wipe
}

// MARK: - ZeroizedData

public final class ZeroizedData {

    // MARK: - Nested Error Type

    public enum ZeroizedDataError: Error, Equatable {
        case wiped          // underlying buffer already zeroized
        case invalidState   // unexpected nil buffer / corruption
    }

    // MARK: - Internal Storage

    private var pointer: UnsafeMutablePointer<UInt8>?
    private(set) public var count: Int
    private let policy: ZeroizePolicy
    private var hasReadOnce = false

    /// Whether memory has been wiped or buffer is unavailable.
    public var isWiped: Bool {
        pointer == nil || count == 0
    }

    // MARK: - Initializers

    public init(copying data: Data, policy: ZeroizePolicy = .onDeinit) {
        self.count = data.count
        self.policy = policy

        if data.isEmpty {
            self.pointer = nil
            return
        }

        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        data.copyBytes(to: ptr, count: data.count)
        self.pointer = ptr
    }

    public init(copying bytes: some Collection<UInt8>, policy: ZeroizePolicy = .onDeinit) {
        let array = Array(bytes)
        self.count = array.count
        self.policy = policy

        if array.isEmpty {
            self.pointer = nil
            return
        }

        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: array.count)
        ptr.initialize(from: array, count: array.count)
        self.pointer = ptr
    }

    deinit {
        if policy != .manual {
            wipe()
        }
    }

    // MARK: - Access

    /// Read-only access to the underlying bytes without copying.
    /// - `.afterRead` → wipes immediately after first access.
    @discardableResult
    public func withBytes<R>(_ body: (UnsafeBufferPointer<UInt8>) throws -> R) throws -> R {
        guard let ptr = pointer, count > 0 else {
            throw ZeroizedDataError.wiped
        }

        let buffer = UnsafeBufferPointer(start: ptr, count: count)
        let result = try body(buffer)

        if policy == .afterRead && !hasReadOnce {
            hasReadOnce = true
            wipe()
        }

        return result
    }

    /// Mutable access for in-place modification.
    /// Does *not* trigger wipe-after-read behavior.
    @discardableResult
    public func withMutableBytes<R>(
        _ body: (UnsafeMutableBufferPointer<UInt8>) throws -> R
    ) throws -> R {

        guard let ptr = pointer, count > 0 else {
            throw ZeroizedDataError.wiped
        }

        let buffer = UnsafeMutableBufferPointer(start: ptr, count: count)
        return try body(buffer)
    }

    // MARK: - Wipe

    /// Zeroizes memory and deallocates buffer. Safe to call multiple times.
    public func wipe() {
        guard let ptr = pointer, count > 0 else {
            pointer = nil
            count = 0
            return
        }

        memset(ptr, 0, count)
        ptr.deallocate()

        pointer = nil
        count = 0
    }
}
