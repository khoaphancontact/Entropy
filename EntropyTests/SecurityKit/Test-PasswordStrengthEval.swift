//
//  Test-PasswordStrengthEval.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  Test-PasswordStrengthEvaluator.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class PasswordStrengthEvaluatorTests: XCTestCase {

    func testEvaluateThrowsNotImplementedForNow() throws {
        let pwd = ZeroizedData(copying: Data("Test123!".utf8))

        XCTAssertThrowsError(try PasswordStrengthEvaluator.evaluate(pwd)) { error in
            XCTAssertEqual(error as? PasswordStrengthError, .notImplemented)
        }
    }

    func testStrengthOnlyThrowsNotImplementedForNow() throws {
        let pwd = ZeroizedData(copying: Data("another-password".utf8))

        XCTAssertThrowsError(try PasswordStrengthEvaluator.strengthOnly(pwd)) { error in
            XCTAssertEqual(error as? PasswordStrengthError, .notImplemented)
        }
    }

    func testPasswordStrengthEnumIsSerializable() throws {
        let strength: PasswordStrength = .high
        let encoded = try JSONEncoder().encode(strength)
        let decoded = try JSONDecoder().decode(PasswordStrength.self, from: encoded)
        XCTAssertEqual(decoded, .high)
    }

    func testPasswordStrengthResultCodableRoundTrip() throws {
        let result = PasswordStrengthResult(
            strength: .medium,
            score: 65,
            estimatedEntropyBits: 48.5,
            length: 16
        )

        let encoded = try JSONEncoder().encode(result)
        let decoded = try JSONDecoder().decode(PasswordStrengthResult.self, from: encoded)

        XCTAssertEqual(decoded, result)
    }
}
