//
//  Test-AutofillDomainMatcher.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/9/25.
//

//
//  AutofillDomainMatcherTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class AutofillDomainMatcherTests: XCTestCase {

    // MARK: - Exact match

    func testExactMatchSameDomain() {
        XCTAssertTrue(
            AutofillDomainMatcher.matches(
                entryDomain: "example.com",
                requestDomain: "example.com"
            )
        )
    }

    func testExactMatchIsCaseInsensitive() {
        XCTAssertTrue(
            AutofillDomainMatcher.matches(
                entryDomain: "Example.COM",
                requestDomain: "EXAMPLE.com"
            )
        )
    }

    func testExactMatchFromURL() {
        XCTAssertTrue(
            AutofillDomainMatcher.matches(
                entryDomain: "example.com",
                requestDomain: "https://example.com/login"
            )
        )
    }

    // MARK: - Subdomain allowed / disallowed

    func testSubdomainNotAllowedByDefault() {
        // accounts.example.com should NOT match example.com when subdomains are disallowed
        XCTAssertFalse(
            AutofillDomainMatcher.matches(
                entryDomain: "example.com",
                requestDomain: "accounts.example.com"
            )
        )
    }

    func testSubdomainAllowedWhenOptionEnabled() {
        let options = DomainMatchOptions(allowSubdomains: true)

        XCTAssertTrue(
            AutofillDomainMatcher.matches(
                entryDomain: "example.com",
                requestDomain: "accounts.example.com",
                options: options
            )
        )

        // Multiple levels should still match if suffix is correct
        XCTAssertTrue(
            AutofillDomainMatcher.matches(
                entryDomain: "example.com",
                requestDomain: "login.accounts.example.com",
                options: options
            )
        )
    }

    // MARK: - Punycode / Unicode (basic behavior)

    func testPunycodeDomainMatchesItself() {
        // Punycode stays ASCII; we just ensure our normalization doesn't break it.
        let puny = "xn--d1acpjx3f.xn--p1ai" // example for "пример.рф"

        XCTAssertTrue(
            AutofillDomainMatcher.matches(
                entryDomain: puny,
                requestDomain: puny
            )
        )
    }

    func testUnicodeDomainMatchesItself() {
        let unicode = "пример.рф"

        XCTAssertTrue(
            AutofillDomainMatcher.matches(
                entryDomain: unicode,
                requestDomain: unicode
            )
        )
    }

    // MARK: - Phishing-like domain rejection

    func testPhishingLikeDomainIsRejected() {
        // Classic phishing trick: "apple.com.evil.co"
        let options = DomainMatchOptions(allowSubdomains: true)

        XCTAssertFalse(
            AutofillDomainMatcher.matches(
                entryDomain: "apple.com",
                requestDomain: "apple.com.evil.co",
                options: options
            )
        )

        XCTAssertFalse(
            AutofillDomainMatcher.matches(
                entryDomain: "google.com",
                requestDomain: "google.com.evil.com",
                options: options
            )
        )
    }

    // MARK: - Invalid / empty inputs

    func testEmptyEntryDomainRejects() {
        XCTAssertFalse(
            AutofillDomainMatcher.matches(
                entryDomain: "",
                requestDomain: "example.com"
            )
        )
    }

    func testEmptyRequestDomainRejects() {
        XCTAssertFalse(
            AutofillDomainMatcher.matches(
                entryDomain: "example.com",
                requestDomain: ""
            )
        )
    }

    func testGarbageInputRejects() {
        XCTAssertFalse(
            AutofillDomainMatcher.matches(
                entryDomain: "example.com",
                requestDomain: "not a url ** and not a domain"
            )
        )
    }
}
