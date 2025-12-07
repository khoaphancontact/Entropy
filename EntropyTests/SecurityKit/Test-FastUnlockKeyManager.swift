//
//  Test-FastUnlockKeyManager.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

import XCTest
@testable import Entropy

final class FastUnlockKeyManagerTests: XCTestCase {

    // MARK: - Helpers

    private func makeKeyData() throws -> Data {
        try SecureRandom.bytes(count: 32)
    }

    private func waitShort() async {
        try? await Task.sleep(nanoseconds: 5_000_000) // 5ms
    }

    // Ensures a clean Keychain before/after each test
    override func setUp() {
        super.setUp()
        let mgr = FastUnlockKeyManager()

        try? blockingAwait {
            try await mgr.invalidateKey()
        }
    }

    override func tearDown() {
        let mgr = FastUnlockKeyManager()

        try? blockingAwait {
            try await mgr.invalidateKey()
        }

        super.tearDown()
    }

    // MARK: - Basic generation

    func testGenerateAndStoreFastUnlockKey() async throws {
        let mgr = FastUnlockKeyManager()

        let key = try await mgr.generateAndStoreFastUnlockKey(policy: .timeLimited(seconds: 10))
        XCTAssertEqual(key.count, 32)

        await XCTAssertAsyncTrue { await mgr.hasValidKey() }
        await XCTAssertAsyncNotNil { await mgr.getKey() }
    }

    // MARK: - Policy none

    func testPolicyNoneDoesNotStoreKey() async throws {
        let mgr = FastUnlockKeyManager()

        await XCTAssertThrowsErrorAsync({
            _ = try await mgr.generateAndStoreFastUnlockKey(policy: .none)
        }) { error in
            XCTAssertEqual(error as? FastUnlockKeyError, .policyExpired)
        }

        await XCTAssertAsyncFalse { await mgr.hasValidKey() }
        await XCTAssertAsyncNil { await mgr.getKey() }
    }

    // MARK: - Expiration

    func testTimeLimitedPolicyExpires() async throws {
        let mgr = FastUnlockKeyManager()

        _ = try await mgr.generateAndStoreFastUnlockKey(policy: .timeLimited(seconds: 1))

        await XCTAssertAsyncTrue { await mgr.hasValidKey(at: Date()) }

        // Simulate 5 seconds later
        let now = Date().addingTimeInterval(5)

        await XCTAssertAsyncFalse { await mgr.hasValidKey(at: now) }
        await XCTAssertAsyncNil { await mgr.getKey(at: now) }
    }

    // MARK: - Lifecycle

    func testLifecycleBackgroundInvalidatesHybridPolicy() async throws {
        let mgr = FastUnlockKeyManager()

        _ = try await mgr.generateAndStoreFastUnlockKey(policy: .hybrid(seconds: 60))

        await XCTAssertAsyncTrue { await mgr.hasValidKey() }

        // Mark app backgrounded
        await mgr.updateLifecycle(appDidBackground: true)

        await XCTAssertAsyncFalse { await mgr.hasValidKey() }
        await XCTAssertAsyncNil { await mgr.getKey() }
    }

    func testLifecycleDeviceLockInvalidatesFastUnlock() async throws {
        let mgr = FastUnlockKeyManager()

        _ = try await mgr.generateAndStoreFastUnlockKey(policy: .hybrid(seconds: 60))

        await mgr.updateLifecycle(deviceDidLock: true)

        await XCTAssertAsyncFalse { await mgr.hasValidKey() }
        await XCTAssertAsyncNil { await mgr.getKey() }
    }

    // MARK: - Reloading from secure storage

    func testReloadFromSecureStorage() async throws {
        let mgr = FastUnlockKeyManager()

        let generated = try await mgr.generateAndStoreFastUnlockKey(policy: .timeLimited(seconds: 10))

        try await waitShort()

        let reloaded = try await mgr.reloadFromSecureStorage()
        XCTAssertEqual(reloaded.count, generated.count)
    }

    func testReloadFailsIfNoKeyInMemory() async throws {
        let mgr = FastUnlockKeyManager()

        await XCTAssertThrowsErrorAsync({
            _ = try await mgr.reloadFromSecureStorage()
        }) { error in
            XCTAssertEqual(error as? FastUnlockKeyError, .keyNotAvailable)
        }
    }

    func testReloadFailsIfPolicyExpired() async throws {
        let mgr = FastUnlockKeyManager()

        _ = try await mgr.generateAndStoreFastUnlockKey(policy: .timeLimited(seconds: 1))

        // Simulate expiration
        let now = Date().addingTimeInterval(3)

        await XCTAssertThrowsErrorAsync({
            _ = try await mgr.reloadFromSecureStorage(at: now)
        }) { error in
            XCTAssertEqual(error as? FastUnlockKeyError, .policyExpired)
        }
    }

    // MARK: - Invalidation

    func testInvalidateKeyWipesEverything() async throws {
        let mgr = FastUnlockKeyManager()

        _ = try await mgr.generateAndStoreFastUnlockKey(policy: .timeLimited(seconds: 10))

        try await mgr.invalidateKey()

        await XCTAssertAsyncFalse { await mgr.hasValidKey() }
        await XCTAssertAsyncNil { await mgr.getKey() }

        await XCTAssertThrowsErrorAsync({
            _ = try await mgr.reloadFromSecureStorage()
        }) { error in
            XCTAssertEqual(error as? FastUnlockKeyError, .keyNotAvailable)
        }
    }

    // MARK: - Background tasks shouldn't crash

    func testBackgroundInvalidationDoesNotCrash() async throws {
        let mgr = FastUnlockKeyManager()

        await mgr.updateLifecycle(appDidBackground: true)
        await XCTAssertAsyncFalse { await mgr.hasValidKey() }
    }
}

// MARK: - Async assertion helpers

/// Synchronous wrapper for async actor calls inside setUp/tearDown
func blockingAwait(_ operation: @escaping () async throws -> Void) throws {
    let semaphore = DispatchSemaphore(value: 0)
    var caughtError: Error?

    Task {
        do { try await operation() }
        catch { caughtError = error }
        semaphore.signal()
    }

    semaphore.wait()

    if let err = caughtError {
        throw err
    }
}

func XCTAssertAsyncTrue(
    _ expression: @escaping () async -> Bool,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #file, line: UInt = #line
) async {
    let result = await expression()
    if !result {
        XCTFail(message(), file: file, line: line)
    }
}

func XCTAssertAsyncFalse(
    _ expression: @escaping () async -> Bool,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #file, line: UInt = #line
) async {
    let result = await expression()
    if result {
        XCTFail(message(), file: file, line: line)
    }
}

func XCTAssertAsyncNil<T>(
    _ expression: @escaping () async -> T?,
    file: StaticString = #file, line: UInt = #line
) async {
    let value = await expression()
    if value != nil {
        XCTFail("Expected nil, got \(String(describing: value))", file: file, line: line)
    }
}

func XCTAssertAsyncNotNil<T>(
    _ expression: @escaping () async -> T?,
    file: StaticString = #file, line: UInt = #line
) async {
    let value = await expression()
    if value == nil {
        XCTFail("Expected non-nil optional", file: file, line: line)
    }
}

func XCTAssertAsyncEqual<T: Equatable>(
    _ lhs: @escaping () async -> T,
    _ rhs: T,
    file: StaticString = #file, line: UInt = #line
) async {
    let l = await lhs()
    if l != rhs {
        XCTFail("Expected \(rhs), got \(l)", file: file, line: line)
    }
}

func XCTAssertThrowsErrorAsync(
    _ operation: @escaping () async throws -> Void,
    _ handler: (Error) -> Void = { _ in },
    file: StaticString = #file, line: UInt = #line
) async {
    do {
        try await operation()
        XCTFail("Expected error but none thrown", file: file, line: line)
    } catch {
        handler(error)
    }
}

func XCTAssertNoThrowAsync(
    _ operation: @escaping () async throws -> Void,
    file: StaticString = #file, line: UInt = #line
) async {
    do { try await operation() }
    catch { XCTFail("Unexpected error: \(error)", file: file, line: line) }
}
