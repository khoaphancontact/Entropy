//
//  Test-VaultUnlockEngine.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/10/25.
//

//
//  VaultUnlockEngineTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy   // adjust to your app module name

final class VaultUnlockEngineTests: XCTestCase {

    // MARK: - Helpers

    private func makeTempVaultURL() -> URL {
        let base = FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("VaultUnlockTests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("TestVault.entropyvault", isDirectory: false)
    }

    /// Small Argon2 params for tests (faster than production values).
    private func testArgon2Params() -> Argon2Params {
        Argon2Params(
            memoryKiB: 32_768,
            iterations: 2,
            parallelism: 1,
            saltLength: 16,
            outputLength: 32
        )
    }

    /// Build a minimal VaultModelV1 with no entries/folders.
    private func emptyModel(now: Date = Date()) -> VaultModelV1 {
        VaultModelV1(
            schemaVersion: VaultFileHeader.currentSchemaVersion,
            createdAt: now,
            modifiedAt: now,
            entries: [:],
            folders: [],
            otpBlocks: [:]
        )
    }

    /// Build a vault file on disk + key bundle, returning everything needed to test unlock.
    private func createTestVault(
        passwordString: String = "Correct-Horse-Battery-Staple"
    ) throws -> (url: URL, bundle: VaultKeyBundleV1, model: VaultModelV1) {

        let url = makeTempVaultURL()
        let now = Date()

        // 1) Derive KDF bundle + vault key
        let pwdData = Data(passwordString.utf8)
        let params = testArgon2Params()

        let (bundle, vaultKey) = try VaultKeyDerivation.createBundleV1(
            password: pwdData,
            params: params
        )

        // 2) Build KDF snapshot for header
        let kdfSnapshot = VaultKDFParamsSnapshot(
            algorithm: .argon2id,
            memoryKiB: params.memoryKiB,
            iterations: params.iterations,
            parallelism: params.parallelism,
            saltLength: params.saltLength
        )

        // 3) Build header + empty model
        let header = VaultFileHeader.newVaultHeader(
            now: now,
            kdfParams: kdfSnapshot
        )
        let model = emptyModel(now: now)

        // 4) Encode vault file
        let fileData = try VaultSerialization.encode(
            model: model,
            vaultKey: vaultKey
        )

        // 5) Write to disk atomically
        try VaultFileIO.writeVaultFile(fileData, to: url)

        return (url, bundle, model)
    }

    // MARK: - Tests

    func testUnlockWithCorrectPasswordSucceeds() throws {
        let password = "Correct-Horse-Battery-Staple"
        let (url, bundle, _) = try createTestVault(passwordString: password)

        let engine = VaultUnlockEngine(
            vaultURL: url,
            keyBundle: bundle
        )

        let passwordZeroized = ZeroizedData(copying: Data(password.utf8))

        let result = try engine.unlockVault(password: passwordZeroized)

        // Basic sanity checks
        XCTAssertEqual(result.header.vaultVersion, VaultFileHeader.currentVaultVersion)
        XCTAssertEqual(result.model.schemaVersion, VaultFileHeader.currentSchemaVersion)
    }

    func testUnlockWithWrongPasswordFails() throws {
        let (url, bundle, _) = try createTestVault(passwordString: "Correct-Horse-Battery-Staple")

        let engine = VaultUnlockEngine(
            vaultURL: url,
            keyBundle: bundle
        )

        let wrongPassword = ZeroizedData(copying: Data("wrong-password".utf8))

        XCTAssertThrowsError(try engine.unlockVault(password: wrongPassword)) { error in
            guard let unlockError = error as? VaultUnlockError else {
                XCTFail("Expected VaultUnlockError, got \(error)")
                return
            }
            XCTAssertEqual(unlockError, .invalidPassword)
        }
    }

    func testCorruptedCiphertextFails() throws {
        let password = "Correct-Horse-Battery-Staple"

        // We do NOT call createTestVault here on purpose to avoid Argon2 / file IO.
        // Build a dummy bundle that will never actually be used because header decode will fail first.
        let dummyParams = Argon2Params(
            memoryKiB: 32_768,
            iterations: 2,
            parallelism: 1,
            saltLength: 16,
            outputLength: 32
        )

        let dummyBundle = VaultKeyBundleV1(
            kdfParams: dummyParams,
            salt: Data(repeating: 0, count: dummyParams.saltLength),
            vaultKeyCiphertext: Data([0x00]),                 // unused
            vaultKeyNonce: Data(repeating: 0, count: 12)      // unused
        )

        // Obviously invalid vault bytes – guaranteed not to decode as a valid VaultFileHeader.
        let corruptedData = Data([0x00, 0x01, 0x02, 0x03])

        // Inject corruptedData via the test-only initializer so nothing touches the filesystem.
        let engine = VaultUnlockEngine(
            fileLoader: { corruptedData },
            keyBundle: dummyBundle
        )

        let passwordZeroized = ZeroizedData(copying: Data(password.utf8))

        XCTAssertThrowsError(try engine.unlockVault(password: passwordZeroized)) { error in
            guard let unlockError = error as? VaultUnlockError else {
                XCTFail("Expected VaultUnlockError, got \(error)")
                return
            }
            XCTAssertEqual(unlockError, .corruptedVault)
        }
    }
}
