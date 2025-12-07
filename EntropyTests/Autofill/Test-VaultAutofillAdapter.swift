//
//  Test-VaultAutofillAdapter.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  Test-VaultAutofillAdapter.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class VaultAutofillAdapterTests: XCTestCase {

    func testPlaceholderAdapterAlwaysThrowsNotImplemented() {
        let adapter = PlaceholderVaultAutofillAdapter()
        let id = UUID()

        XCTAssertThrowsError(
            try adapter.makePasswordPayload(for: id, requestedDomain: "example.com")
        ) { error in
            XCTAssertEqual(error as? VaultAutofillAdapterError, .notImplemented)
        }
    }

    func testAdapterErrorsAreEquatable() {
        XCTAssertEqual(VaultAutofillAdapterError.notImplemented,
                       VaultAutofillAdapterError.notImplemented)

        XCTAssertNotEqual(VaultAutofillAdapterError.notImplemented,
                          VaultAutofillAdapterError.entryNotFound)
    }
}
