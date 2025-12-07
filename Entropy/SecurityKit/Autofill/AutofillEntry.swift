//
//  AutofillEntry.swift
//  Entropy
//

import Foundation

public struct AutofillEntry: Sendable {
    public let entryID: UUID
    public let title: String
    public let domain: String?
    public let username: ZeroizedData
    public let password: ZeroizedData
    public let otpSecret: ZeroizedData?

    public init(
        entryID: UUID,
        title: String,
        domain: String?,
        username: ZeroizedData,
        password: ZeroizedData,
        otpSecret: ZeroizedData? = nil
    ) {
        self.entryID = entryID
        self.title = title
        self.domain = domain
        self.username = username
        self.password = password
        self.otpSecret = otpSecret
    }
}

// MARK: - Manual Equatable (secure, constant-time comparisons)

extension AutofillEntry: Equatable {
    public static func == (lhs: AutofillEntry, rhs: AutofillEntry) -> Bool {

        // Compare non-sensitive fields normally
        guard lhs.entryID == rhs.entryID,
              lhs.title == rhs.title,
              lhs.domain == rhs.domain else {
            return false
        }

        // Compare sensitive fields using constant-time compare
        let userEqual: Bool = {
            let l = (try? lhs.username.withBytes { Data($0) }) ?? Data()
            let r = (try? rhs.username.withBytes { Data($0) }) ?? Data()
            return SecureCompare.equal(l, r)
        }()

        let passEqual: Bool = {
            let l = (try? lhs.password.withBytes { Data($0) }) ?? Data()
            let r = (try? rhs.password.withBytes { Data($0) }) ?? Data()
            return SecureCompare.equal(l, r)
        }()

        let otpEqual: Bool = {
            switch (lhs.otpSecret, rhs.otpSecret) {
            case (.none, .none):
                return true
            case let (.some(l), .some(r)):
                let ld = (try? l.withBytes { Data($0) }) ?? Data()
                let rd = (try? r.withBytes { Data($0) }) ?? Data()
                return SecureCompare.equal(ld, rd)
            default:
                return false
            }
        }()

        return userEqual && passEqual && otpEqual
    }
}
