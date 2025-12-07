//
//  Test-SecureCompare.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

import XCTest
@testable import Entropy

final class SecureCompareTests: XCTestCase {

    func testSecureCompareData() {
        let a = Data([1, 2, 3, 4, 5])
        let b = Data([1, 2, 3, 4, 5])
        let c = Data([1, 2, 3, 4, 9])
        let d = Data([1, 2, 3])

        XCTAssertTrue(SecureCompare.equal(a, b), "Equal buffers should compare equal")
        XCTAssertFalse(SecureCompare.equal(a, c), "Different contents should compare false")
        XCTAssertFalse(SecureCompare.equal(a, d), "Different lengths should compare false")
    }

    func testSecureCompareRawBuffers() {
        let bytesA: [UInt8] = [10, 20, 30]
        let bytesB: [UInt8] = [10, 20, 30]
        let bytesC: [UInt8] = [10, 20, 31]

        bytesA.withUnsafeBytes { bufA in
            bytesB.withUnsafeBytes { bufB in
                XCTAssertTrue(SecureCompare.equal(bufA, bufB))
            }
        }

        bytesA.withUnsafeBytes { bufA in
            bytesC.withUnsafeBytes { bufC in
                XCTAssertFalse(SecureCompare.equal(bufA, bufC))
            }
        }
    }
}
