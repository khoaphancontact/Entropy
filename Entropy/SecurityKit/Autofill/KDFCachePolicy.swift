//
//  KDFCachePolicy.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/6/25.
//

//
//  KDFCachePolicy.swift
//  Entropy
//
//  Defines how long derived keys (e.g., Argon2 master keys) may be cached in memory
//  for fast unlock / autofill flows. This MUST never allow disk persistence.
//
import Foundation

/// Represents how long a derived key (e.g., Argon2 master key) may be cached in memory.
///
/// This is intentionally conservative. Any cached key:
/// - Lives only in RAM
/// - Is held in ZeroizedData
/// - MUST be wiped on expiry, app background, or device lock (enforced by higher layers).
public enum KDFCachePolicy: Equatable, Sendable {

    /// Never cache derived keys. Argon2 must run on every unlock.
    case none

    /// Cache the key until a fixed time interval has elapsed
    /// since it was created (e.g., 15–60 seconds).
    case timeLimited(seconds: TimeInterval)

    /// Cache only while the app is in the foreground.
    /// Must be dropped when app enters background or extension is deactivated.
    case untilAppBackground

    /// Cache until the next device lock (screen lock).
    /// Requires higher layers to observe `UIApplication.protectedDataWillBecomeUnavailableNotification`
    /// / equivalent signals and purge.
    case untilDeviceLock

    /// Cache until both:
    /// - A fixed time interval has elapsed, AND
    /// - The app has not gone to background / device lock.
    case hybrid(seconds: TimeInterval)

    /// Returns `true` if this policy *ever* allows caching.
    public var allowsCaching: Bool {
        switch self {
        case .none:
            return false
        case .timeLimited, .untilAppBackground, .untilDeviceLock, .hybrid:
            return true
        }
    }
}

/// Tracks a single cached KDF result (e.g., master key) and its expiry semantics.
///
/// This does NOT hold the key itself; it only reasons about when the key should be considered invalid.
/// The actual key should live in `ZeroizedData` elsewhere and be zeroized as soon as this says it expired.
public struct KDFCacheState: Equatable, Sendable {
    public let policy: KDFCachePolicy
    public let createdAt: Date

    /// Optional: externally driven flags about app lifecycle.
    /// These are *not* managed here; higher layers must toggle them.
    public var didAppGoToBackground: Bool
    public var didDeviceLock: Bool

    public init(policy: KDFCachePolicy,
                createdAt: Date = Date(),
                didAppGoToBackground: Bool = false,
                didDeviceLock: Bool = false) {
        self.policy = policy
        self.createdAt = createdAt
        self.didAppGoToBackground = didAppGoToBackground
        self.didDeviceLock = didDeviceLock
    }

    /// Returns true if, according to this policy and current wall clock,
    /// the cached key should be treated as expired and destroyed.
    public func isExpired(at date: Date = Date()) -> Bool {
        switch policy {
        case .none:
            return true

        case .timeLimited(let seconds):
            return date.timeIntervalSince(createdAt) >= seconds

        case .untilAppBackground:
            return didAppGoToBackground

        case .untilDeviceLock:
            return didDeviceLock

        case .hybrid(let seconds):
            let timedOut = date.timeIntervalSince(createdAt) >= seconds
            return timedOut || didAppGoToBackground || didDeviceLock
        }
    }

    /// Returns a copy updated with lifecycle changes.
    public func withLifecycleUpdate(appBackgrounded: Bool? = nil,
                                    deviceLocked: Bool? = nil) -> KDFCacheState {
        KDFCacheState(
            policy: policy,
            createdAt: createdAt,
            didAppGoToBackground: appBackgrounded ?? didAppGoToBackground,
            didDeviceLock: deviceLocked ?? didDeviceLock
        )
    }
}
