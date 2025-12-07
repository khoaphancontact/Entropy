//
//  Test-AutofillEphemeralMemory.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  AutofillEphemeralMemoryTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy   // Change to SecurityKit if AutofillEntry lives there

final class AutofillEphemeralMemoryTests: XCTestCase {

    // MARK: - Helpers

    private func zd(_ string: String) -> ZeroizedData {
        ZeroizedData(copying: string.data(using: .utf8)!)
    }

    private func makeEntry(
        id: UUID = UUID(),
        domain: String? = "example.com",
        username: String = "alice",
        password: String = "pw",
        otp: String? = nil
    ) -> AutofillEntry {
        AutofillEntry(
            entryID: id,
            title: "Test",
            domain: domain,
            username: zd(username),
            password: zd(password),
            otpSecret: otp.map(zd)
        )
    }

    // MARK: - Store + Peek

    func testStoreAndPeek() async throws {
        let mem = AutofillEphemeralMemory()
        let entry = makeEntry()

        await mem.store(entry, ttl: 30)

        let peeked = try await mem.peek(entryID: entry.entryID)
        XCTAssertEqual(peeked, entry)
    }

    // MARK: - Fetch and Consume

    func testFetchAndConsumeRemovesEntry() async throws {
        let mem = AutofillEphemeralMemory()
        let entry = makeEntry()

        await mem.store(entry, ttl: 30)

        // First fetch succeeds
        let fetched = try await mem.fetchAndConsume(entryID: entry.entryID)
        XCTAssertEqual(fetched, entry)

        await XCTAssertThrowsErrorAsync({
            _ = try await mem.fetchAndConsume(entryID: entry.entryID)
        }) { error in
            XCTAssertEqual(error as? AutofillEphemeralMemoryError, .entryNotFound)
        }
    }

    // MARK: - Expiration

    func testExpiredEntryIsNotReturned() async throws {
        let mem = AutofillEphemeralMemory()
        let entry = makeEntry()

        let now = Date()
        let expiredAt = now.addingTimeInterval(-1)

        // Store entry already expired
        await mem.store(entry, ttl: -1)

        await XCTAssertThrowsErrorAsync({
            _ = try await mem.peek(entryID: entry.entryID, at: expiredAt)
        }) { error in
            XCTAssertEqual(error as? AutofillEphemeralMemoryError, .entryExpired)
        }
    }

    func testPurgeExpiredRemovesOnlyExpiredEntries() async throws {
        let mem = AutofillEphemeralMemory()

        let fresh = makeEntry()
        let expired = makeEntry()

        await mem.store(fresh, ttl: 30)
        await mem.store(expired, ttl: -1)

        let now = Date()
        await mem.purgeExpired(at: now)

        // fresh should still be present
        await XCTAssertNoThrowAsync({
            _ = try await mem.peek(entryID: fresh.entryID)
        })

        // expired should be gone
        await XCTAssertThrowsErrorAsync {
            _ = try await mem.peek(entryID: expired.entryID)
        }
    }

    // MARK: - Domain Matching

    func testDomainMatchingFindsCorrectEntries() async throws {
        let mem = AutofillEphemeralMemory()

        let e1 = makeEntry(domain: "github.com")
        let e2 = makeEntry(domain: "gitlab.com")
        let e3 = makeEntry(domain: "example.com")

        await mem.store(e1)
        await mem.store(e2)
        await mem.store(e3)

        let matches = await mem.entries(matchingDomain: "git")

        XCTAssertTrue(matches.contains(e1))
        XCTAssertTrue(matches.contains(e2))
        XCTAssertFalse(matches.contains(e3))
    }

    func testDomainMatchingIgnoresExpiredEntries() async throws {
        let mem = AutofillEphemeralMemory()

        let valid = makeEntry(domain: "amazon.com")
        let expired = makeEntry(domain: "amazon.com")

        await mem.store(valid, ttl: 30)
        await mem.store(expired, ttl: -1)

        let matches = await mem.entries(matchingDomain: "amazon")
        XCTAssertTrue(matches.contains(valid))
        XCTAssertEqual(matches.count, 1)
    }

    // MARK: - Clear All

    func testClearAllRemovesEverything() async throws {
        let mem = AutofillEphemeralMemory()
        let e1 = makeEntry()
        let e2 = makeEntry()

        await mem.store(e1)
        await mem.store(e2)

        await mem.clearAll()

        await XCTAssertThrowsErrorAsync {
            _ = try await mem.peek(entryID: e1.entryID)
        }
        await XCTAssertThrowsErrorAsync {
            _ = try await mem.peek(entryID: e2.entryID)
        }
    }
}

// MARK: - Async XCTAssert helper

func XCTAssertThrowsErrorAsync(
    _ operation: @escaping () async throws -> Void,
    _ errorHandler: (Error) -> Void = { _ in }
) async {
    do {
        try await operation()
        XCTFail("Expected error but no error was thrown.")
    } catch {
        errorHandler(error)
    }
}

func XCTAssertNoThrowAsync(
    _ operation: @escaping () async throws -> Void,
    _ errorHandler: (Error) -> Void = { _ in }
) async {
    do {
        try await operation()
    } catch {
        XCTFail("Unexpected error thrown: \(error)")
        errorHandler(error)
    }
}
