//
//  Test-VaultEntrySecurityInfo.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultEntrySecurityInfoTests.swift
//  EntropyVaultModelsTests
//

import XCTest
import CryptoKit
@testable import Entropy

final class VaultEntrySecurityInfoTests: XCTestCase {

    // MARK: - Encode / Decode

    func testEncodeDecodeRoundTrip() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fingerprint = Data([0x01, 0x02, 0x03])

        // NOTE: adjust `.medium` if your PasswordStrength uses different cases.
        let original = VaultEntrySecurityInfo(
            strength: .medium,
            score: 85,
            entropyBits: 64.0,
            lastEvaluated: now,
            passwordFingerprint: fingerprint
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(VaultEntrySecurityInfo.self, from: data)

        XCTAssertEqual(decoded, original)
    }

    // MARK: - Default-like init behavior

    func testInitWithOnlyStrengthSetsOptionalsToNil() {
        // only pass required field; everything else should initialize sanely
        let info = VaultEntrySecurityInfo(strength: .medium)

        XCTAssertNil(info.score)
        XCTAssertNil(info.entropyBits)
        XCTAssertNil(info.passwordFingerprint)
        // lastEvaluated is "now" – we just assert it’s not in the distant past
        XCTAssertGreaterThan(info.lastEvaluated.timeIntervalSince1970, 0)
    }

    // MARK: - Backward compatibility: missing fingerprint

    func testMissingPasswordFingerprintDecodesAsNil() throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        // Encode without fingerprint explicitly set (nil)
        let original = VaultEntrySecurityInfo(
            strength: .medium,
            score: nil,
            entropyBits: nil,
            lastEvaluated: now,
            passwordFingerprint: nil
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(VaultEntrySecurityInfo.self, from: data)

        XCTAssertNil(decoded.passwordFingerprint)
        XCTAssertEqual(decoded.strength, original.strength)
        XCTAssertEqual(decoded.lastEvaluated, original.lastEvaluated)
    }

    // MARK: - Fingerprint persistence

    func testPasswordFingerprintPersistsAcrossEncodeDecode() throws {
        let passwordData = Data("example-password".utf8)
        let hash = Data(SHA256.hash(data: passwordData))

        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let original = VaultEntrySecurityInfo(
            strength: .medium,
            score: 90,
            entropyBits: 72.0,
            lastEvaluated: now,
            passwordFingerprint: hash
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(VaultEntrySecurityInfo.self, from: data)

        XCTAssertEqual(decoded.passwordFingerprint, hash)
    }

    // MARK: - Fingerprint equality / reuse detection behavior

    func testIdenticalPasswordsProduceIdenticalFingerprints() {
        let pwd1 = Data("same-password".utf8)
        let pwd2 = Data("same-password".utf8)

        let fp1 = Data(SHA256.hash(data: pwd1))
        let fp2 = Data(SHA256.hash(data: pwd2))

        XCTAssertEqual(fp1, fp2)

        let info1 = VaultEntrySecurityInfo(
            strength: .medium,
            passwordFingerprint: fp1
        )
        let info2 = VaultEntrySecurityInfo(
            strength: .medium,
            passwordFingerprint: fp2
        )

        XCTAssertEqual(info1.passwordFingerprint, info2.passwordFingerprint)
    }

    func testDifferentPasswordsProduceDifferentFingerprints() {
        let pwd1 = Data("password-one".utf8)
        let pwd2 = Data("password-two".utf8)

        let fp1 = Data(SHA256.hash(data: pwd1))
        let fp2 = Data(SHA256.hash(data: pwd2))

        XCTAssertNotEqual(fp1, fp2)

        let info1 = VaultEntrySecurityInfo(
            strength: .medium,
            passwordFingerprint: fp1
        )
        let info2 = VaultEntrySecurityInfo(
            strength: .medium,
            passwordFingerprint: fp2
        )

        XCTAssertNotEqual(info1.passwordFingerprint, info2.passwordFingerprint)
    }
}
