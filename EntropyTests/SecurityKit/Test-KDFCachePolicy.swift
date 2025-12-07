//
//  Test-KDFCachePolicy.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  KDFCachePolicyTests.swift
//  EntropyTests
//

import XCTest
@testable import Entropy

final class KDFCachePolicyTests: XCTestCase {

    func testNoneAlwaysExpired() {
        let state = KDFCacheState(policy: .none)
        XCTAssertTrue(state.isExpired())
    }

    func testTimeLimitedNotExpiredEarly() {
        let state = KDFCacheState(policy: .timeLimited(seconds: 5), createdAt: Date())
        XCTAssertFalse(state.isExpired(at: Date().addingTimeInterval(2)))
    }

    func testTimeLimitedExpiredAfterThreshold() {
        let state = KDFCacheState(policy: .timeLimited(seconds: 5), createdAt: Date().addingTimeInterval(-10))
        XCTAssertTrue(state.isExpired())
    }

    func testUntilAppBackground() {
        var state = KDFCacheState(policy: .untilAppBackground)
        XCTAssertFalse(state.isExpired())

        state = state.withLifecycleUpdate(appBackgrounded: true)
        XCTAssertTrue(state.isExpired())
    }

    func testUntilDeviceLock() {
        var state = KDFCacheState(policy: .untilDeviceLock)
        XCTAssertFalse(state.isExpired())

        state = state.withLifecycleUpdate(deviceLocked: true)
        XCTAssertTrue(state.isExpired())
    }

    func testHybridExpiresByTime() {
        let state = KDFCacheState(
            policy: .hybrid(seconds: 3),
            createdAt: Date().addingTimeInterval(-10),
            didAppGoToBackground: false,
            didDeviceLock: false
        )
        XCTAssertTrue(state.isExpired())
    }

    func testHybridExpiresByBackground() {
        let state = KDFCacheState(
            policy: .hybrid(seconds: 30),
            createdAt: Date(),
            didAppGoToBackground: true,
            didDeviceLock: false
        )
        XCTAssertTrue(state.isExpired())
    }

    func testHybridExpiresByDeviceLock() {
        let state = KDFCacheState(
            policy: .hybrid(seconds: 30),
            createdAt: Date(),
            didAppGoToBackground: false,
            didDeviceLock: true
        )
        XCTAssertTrue(state.isExpired())
    }

    func testHybridNotExpiredWhenAllGood() {
        let state = KDFCacheState(
            policy: .hybrid(seconds: 30),
            createdAt: Date(),
            didAppGoToBackground: false,
            didDeviceLock: false
        )
        XCTAssertFalse(state.isExpired())
    }

    func testAllowsCaching() {
        XCTAssertFalse(KDFCachePolicy.none.allowsCaching)
        XCTAssertTrue(KDFCachePolicy.timeLimited(seconds: 10).allowsCaching)
        XCTAssertTrue(KDFCachePolicy.untilAppBackground.allowsCaching)
        XCTAssertTrue(KDFCachePolicy.untilDeviceLock.allowsCaching)
        XCTAssertTrue(KDFCachePolicy.hybrid(seconds: 10).allowsCaching)
    }
}
