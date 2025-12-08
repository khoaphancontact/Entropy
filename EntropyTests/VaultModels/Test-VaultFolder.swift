//
//  Test-VaultFolder.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  VaultFolderTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class VaultFolderTests: XCTestCase {

    // MARK: - Helpers

    private func makeUUIDs(_ count: Int) -> [UUID] {
        (0..<count).map { _ in UUID() }
    }

    // MARK: - Add Entry

    func testAddEntry() {
        var folder = VaultFolder(name: "Test", orderIndex: 0)
        let ids = makeUUIDs(3)

        folder.addEntry(ids[0])
        folder.addEntry(ids[1])

        XCTAssertEqual(folder.entries.count, 2)
        XCTAssertEqual(folder.entries, [ids[0], ids[1]])

        // Adding duplicate must not change structure
        folder.addEntry(ids[0])
        XCTAssertEqual(folder.entries.count, 2)
    }

    // MARK: - Remove Entry

    func testRemoveEntry() {
        var folder = VaultFolder(name: "Test", orderIndex: 0)
        let ids = makeUUIDs(3)

        folder.addEntry(ids[0])
        folder.addEntry(ids[1])
        folder.addEntry(ids[2])

        folder.removeEntry(ids[1])

        XCTAssertEqual(folder.entries, [ids[0], ids[2]])

        // Removing non-existing entry does nothing
        folder.removeEntry(UUID())
        XCTAssertEqual(folder.entries, [ids[0], ids[2]])
    }

    // MARK: - Rename

    func testRenameFolder() {
        var folder = VaultFolder(name: "OldName", orderIndex: 0)
        folder.rename(to: "NewName")
        XCTAssertEqual(folder.name, "NewName")
    }

    // MARK: - Ordering

    func testFolderOrdering() {
        var folder = VaultFolder(name: "OrderTest", orderIndex: 0)
        let ids = makeUUIDs(3)

        // deterministic insertion order
        folder.addEntry(ids[0])
        folder.addEntry(ids[2])
        folder.addEntry(ids[1])

        XCTAssertEqual(folder.orderedEntries(), [ids[0], ids[2], ids[1]])
    }

    // MARK: - Codable

    func testCodableRoundTrip() throws {
        let ids = makeUUIDs(3)
        var folder = VaultFolder(name: "Codable", orderIndex: 2)
        folder.addEntry(ids[0])
        folder.addEntry(ids[1])
        folder.addEntry(ids[2])

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]

        let data = try encoder.encode(folder)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(VaultFolder.self, from: data)

        XCTAssertEqual(decoded, folder)
    }
}
