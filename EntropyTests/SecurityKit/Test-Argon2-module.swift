//
//  Test-Argon2-module.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//


import XCTest
@testable import Entropy

final class Argon2LinkTests: XCTestCase {

    func testArgon2Link() {
        // This confirms the argon2 library is linked and version constant is visible.
        print("Argon2 version:", ARGON2_VERSION_NUMBER)

        // You can also assert it's nonzero if needed:
        XCTAssertNotEqual(Int(ARGON2_VERSION_NUMBER.rawValue), 0)
    }
}

