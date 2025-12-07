//  ZeroizedData.swift
//  Entropy
//
//  Secure container for sensitive bytes that zeroizes memory on wipe/deinit
//

//  ZeroizedData.swift
//  Entropy
//
//  Secure container for sensitive bytes that zeroizes memory on wipe/deinit.
//

import Foundation

/// Errors thrown by ZeroizedData when accessing wiped or invalid memory.
public enum ZeroizedDataError: Error, Equatable {
    case wiped
    case invalidState
}

/// A secure, zeroizing container for sensitive bytes.
/// - Stores bytes in manually managed heap memory (UnsafeMutablePointer<UInt8>).
/// - Provides controlled access via buffer pointers to avoid implicit copies.
/// - Supports in-place mutation through a mutable buffer.
/// - Zeroizes memory on wipe() and on deinit.
public final class ZeroizedData {
    // MARK: - Storage
    
    private var pointer: UnsafeMutablePointer<UInt8>?
    private(set) public var count: Int
    
    /// Whether the underlying memory has been wiped/freed.
    public var isWiped: Bool {
        return pointer == nil || count == 0
    }
    
    // MARK: - Init
    
    /// Initialize by copying from a Data buffer.
    public init(copying data: Data) {
        self.count = data.count
        if data.isEmpty {
            self.pointer = nil
            return
        }
        
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        data.copyBytes(to: ptr, count: data.count)
        self.pointer = ptr
    }
    
    /// Initialize by copying from a collection of bytes.
    public init(copying bytes: some Collection<UInt8>) {
        let byteArray = Array(bytes)
        self.count = byteArray.count
        if byteArray.isEmpty {
            self.pointer = nil
            return
        }
        
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: byteArray.count)
        ptr.initialize(from: byteArray, count: byteArray.count)
        self.pointer = ptr
    }
    
    deinit {
        wipe()
    }
    
    // MARK: - Accessors
    
    /// Provides read-only access to the underlying bytes without implicit copying.
    /// Throws if the data has been wiped.
    @discardableResult
    public func withBytes<R>(_ body: (UnsafeBufferPointer<UInt8>) throws -> R) throws -> R {
        guard let ptr = pointer, count > 0 else {
            throw ZeroizedDataError.wiped
        }
        let buffer = UnsafeBufferPointer(start: ptr, count: count)
        return try body(buffer)
    }
    
    /// Provides mutable access to the underlying bytes for in-place mutation.
    /// Throws if the data has been wiped.
    @discardableResult
    public func withMutableBytes<R>(_ body: (UnsafeMutableBufferPointer<UInt8>) throws -> R) throws -> R {
        guard let ptr = pointer, count > 0 else {
            throw ZeroizedDataError.wiped
        }
        let buffer = UnsafeMutableBufferPointer(start: ptr, count: count)
        return try body(buffer)
    }
    
    // MARK: - Wipe
    
    /// Wipes the underlying memory by zeroing all bytes and deallocating the buffer.
    /// Safe to call multiple times; subsequent calls are no-ops.
    public func wipe() {
        guard let ptr = pointer, count > 0 else {
            pointer = nil
            count = 0
            return
        }
        
        // Overwrite bytes with zeros
        for i in 0..<count {
            ptr.advanced(by: i).pointee = 0
        }
        
        // Deallocate the memory
        ptr.deallocate()
        
        // Mark as wiped
        pointer = nil
        count = 0
    }
}
