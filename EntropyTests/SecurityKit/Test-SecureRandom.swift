//
//  Test-SecureRandom.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

import XCTest
@testable import Entropy

final class SecureRandomTests: XCTestCase {

    func testRandomBytesGeneration() throws {
        let bytes1 = try SecureRandom.bytes(count: 32)
        let bytes2 = try SecureRandom.bytes(count: 32)

        XCTAssertEqual(bytes1.count, 32)
        XCTAssertEqual(bytes2.count, 32)
        XCTAssertNotEqual(bytes1, bytes2, "Two random buffers should not be identical")
    }

    func testFillBuffer() throws {
        var array = [UInt8](repeating: 0, count: 16)

        try array.withUnsafeMutableBytes { rawBuf in
            try SecureRandom.fill(rawBuf)
        }

        XCTAssertFalse(array.allSatisfy { $0 == 0 }, "Buffer should not be all zeros after fill()")
    }

    func testUInt64Generation() throws {
        let value = try SecureRandom.uint64()
        XCTAssertNotEqual(value, 0, "Random UInt64 should rarely be zero")
    }

    func testZeroLengthBytes() throws {
        let empty = try SecureRandom.bytes(count: 0)
        XCTAssertEqual(empty.count, 0)
    }
}
