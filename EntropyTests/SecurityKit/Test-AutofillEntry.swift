//
//  Test-AutofillEntry.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  AutofillEntryTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class AutofillEntryTests: XCTestCase {

    private func zd(_ string: String) -> ZeroizedData {
        ZeroizedData(copying: string.data(using: .utf8)!)
    }

    // MARK: - Equality Tests

    func testAutofillEntryEqualitySuccess() throws {
        let entryID = UUID()
        let e1 = AutofillEntry(
            entryID: entryID,
            title: "GitHub",
            domain: "github.com",
            username: zd("user123"),
            password: zd("pass123"),
            otpSecret: zd("otpsecret")
        )

        let e2 = AutofillEntry(
            entryID: entryID,
            title: "GitHub",
            domain: "github.com",
            username: zd("user123"),
            password: zd("pass123"),
            otpSecret: zd("otpsecret")
        )

        XCTAssertEqual(e1, e2)
    }

    func testAutofillEntryEqualityFailsForDifferentUsername() throws {
        let entryID = UUID()
        let e1 = AutofillEntry(
            entryID: entryID,
            title: "Service",
            domain: "example.com",
            username: zd("alice"),
            password: zd("pw"),
            otpSecret: nil
        )

        let e2 = AutofillEntry(
            entryID: entryID,
            title: "Service",
            domain: "example.com",
            username: zd("bob"),   // different
            password: zd("pw"),
            otpSecret: nil
        )

        XCTAssertNotEqual(e1, e2)
    }

    func testAutofillEntryEqualityFailsForDifferentPassword() throws {
        let entryID = UUID()
        let e1 = AutofillEntry(
            entryID: entryID,
            title: "Service",
            domain: nil,
            username: zd("user"),
            password: zd("pw1"),
            otpSecret: nil
        )

        let e2 = AutofillEntry(
            entryID: entryID,
            title: "Service",
            domain: nil,
            username: zd("user"),
            password: zd("pw2"),  // different
            otpSecret: nil
        )

        XCTAssertNotEqual(e1, e2)
    }

    func testAutofillEntryEqualityHandlesNilOTP() throws {
        let entryID = UUID()

        let e1 = AutofillEntry(
            entryID: entryID,
            title: "Test",
            domain: nil,
            username: zd("user"),
            password: zd("pw"),
            otpSecret: nil
        )

        let e2 = AutofillEntry(
            entryID: entryID,
            title: "Test",
            domain: nil,
            username: zd("user"),
            password: zd("pw"),
            otpSecret: nil
        )

        XCTAssertEqual(e1, e2)
    }

    func testAutofillEntryEqualityFailsForDifferentOTP() throws {
        let entryID = UUID()

        let e1 = AutofillEntry(
            entryID: entryID,
            title: "Test",
            domain: nil,
            username: zd("user"),
            password: zd("pw"),
            otpSecret: zd("111111")
        )

        let e2 = AutofillEntry(
            entryID: entryID,
            title: "Test",
            domain: nil,
            username: zd("user"),
            password: zd("pw"),
            otpSecret: zd("222222") // differ
        )

        XCTAssertNotEqual(e1, e2)
    }
}
