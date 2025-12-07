//
//  Test-ZeroizedDataPolicy.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  ZeroizedDataPolicyTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class ZeroizedDataPolicyTests: XCTestCase {

    func testAfterReadWipesImmediately() throws {
        let z = ZeroizedData(copying: Data("Hello".utf8), policy: .afterRead)

        // First read allowed
        try z.withBytes { raw in
            let s = String(data: Data(raw), encoding: .utf8)
            XCTAssertEqual(s, "Hello")
        }

        // Second read should fail because it auto-wiped
        XCTAssertThrowsError(try z.withBytes { _ in }) { error in
            XCTAssertEqual(error as? ZeroizedData.ZeroizedDataError, .wiped)
        }
    }

    func testManualDoesNotWipe() throws {
        let z = ZeroizedData(copying: Data([1, 2, 3]), policy: .manual)

        try z.withBytes { raw in
            XCTAssertEqual(Array(raw), [1, 2, 3])
        }

        try z.withBytes { raw in
            XCTAssertEqual(Array(raw), [1, 2, 3])
        }

        // Caller wipes manually
        z.wipe()

        XCTAssertThrowsError(try z.withBytes { _ in })
    }

    func testOnDeinitWipesOnDeallocation() throws {
        var z: ZeroizedData? = ZeroizedData(copying: Data([9, 9, 9]), policy: .onDeinit)
        weak var weakRef = z

        // Access works before deinit
        try z!.withBytes { raw in
            XCTAssertEqual(Array(raw), [9, 9, 9])
        }

        z = nil  // triggers deinit wipe

        XCTAssertNil(weakRef)
    }
}
