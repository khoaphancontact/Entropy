//
//  Test-FUKMEnclave.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/7/25.
//

//
//  FastUnlockKeyManagerEnclaveTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class FastUnlockKeyManagerEnclaveTests: XCTestCase {

    func testEnclaveAPIStubsThrowNotImplemented() async throws {
        let mgr = FastUnlockKeyManager()

        await XCTAssertThrowsErrorAsync({
            _ = try await mgr.generateSecureEnclaveKeypair()
        }) { err in
            XCTAssertEqual(err as? FastUnlockKeyError, .notImplemented)
        }

        let z = ZeroizedData(copying: Data([1, 2, 3]))

        await XCTAssertThrowsErrorAsync({
            _ = try await mgr.encryptVaultKeyWithEnclavePublicKey(z)
        }) { err in
            XCTAssertEqual(err as? FastUnlockKeyError, .notImplemented)
        }

        await XCTAssertThrowsErrorAsync({
            _ = try await mgr.decryptVaultKeyWithSecureEnclave(Data([0xAA]))
        }) { err in
            XCTAssertEqual(err as? FastUnlockKeyError, .notImplemented)
        }

        await XCTAssertThrowsErrorAsync({
            try await mgr.invalidateEnclaveKeys()
        }) { err in
            XCTAssertEqual(err as? FastUnlockKeyError, .notImplemented)
        }
    }
}
