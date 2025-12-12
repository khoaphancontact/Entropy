//
//  Test-VaultFileIO.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/10/25.
//

//
//  VaultFileIOTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy   // adjust module name if needed

final class VaultFileIOTests: XCTestCase {

    private func makeTempVaultURL() -> URL {
        let base = FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("VaultFileIOTests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("TestVault.entropyvault", isDirectory: false)
    }

    func testVaultPathIsUnderVaultsDirectory() throws {
        let url = try VaultFileLocator.vaultFileURL()
        XCTAssertTrue(url.path.contains("Vaults"))
        XCTAssertTrue(url.lastPathComponent.hasSuffix("Vault.entropyvault"))
    }

    func testReadMissingFileReturnsNil() throws {
        let url = makeTempVaultURL()
        // Ensure it doesn't exist
        try? FileManager.default.removeItem(at: url)

        let data = try VaultFileIO.readVaultIfExists(at: url)
        XCTAssertNil(data)
    }

    func testReadRequiredMissingThrows() {
        let url = makeTempVaultURL()
        try? FileManager.default.removeItem(at: url)

        XCTAssertThrowsError(try VaultFileIO.readVaultRequired(at: url)) { error in
            guard case VaultFileIOError.missingFile = error else {
                XCTFail("Expected missingFile, got \(error)")
                return
            }
        }
    }

    func testWriteAndReadRoundTrip() throws {
        let url = makeTempVaultURL()
        let original = Data("HelloVault".utf8)

        try VaultFileIO.writeVaultFile(original, to: url)

        let loaded = try VaultFileIO.readVaultRequired(at: url)
        XCTAssertEqual(original, loaded)
    }

    func testPermissionsAreRestrictive() throws {
        let url = makeTempVaultURL()
        let data = Data("Secret".utf8)

        try VaultFileIO.writeVaultFile(data, to: url)

        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        if let perms = attrs[.posixPermissions] as? NSNumber {
            XCTAssertEqual(perms.intValue, 0o600, "Vault file should be owner read/write only")
        } else {
            XCTFail("Missing posixPermissions attribute")
        }
    }

    func testOverwriteIsAtomicSemantically() throws {
        let url = makeTempVaultURL()
        let first = Data("FIRST".utf8)
        let second = Data("SECOND-LONGER".utf8)

        try VaultFileIO.writeVaultFile(first, to: url)
        try VaultFileIO.writeVaultFile(second, to: url)

        let loaded = try VaultFileIO.readVaultRequired(at: url)
        XCTAssertEqual(loaded, second, "Final vault content must equal last write, not partial mix")
    }
}
