//
//  VaultSerializationBenchmarks.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/9/25.
//


import XCTest
@testable import Entropy

final class VaultSerializationBenchmarks: XCTestCase {

    private func makeLargeVault(count: Int, key: ZeroizedData) throws -> VaultModelV1 {
        let now = Date()
        var entries: [UUID: VaultEntry] = [:]

        for _ in 0..<count {
            let id = UUID()
            let encUser = try encrypt("user@example.com", key: key, now: now)
            let encPass = try encrypt("P@ssw0rd!", key: key, now: now)

            entries[id] = VaultEntry(
                id: id,
                title: "Example",
                domain: "example.com",
                createdAt: now,
                updatedAt: now,
                encryptedUsername: encUser,
                encryptedPassword: encPass,
                encryptedNotes: nil,
                otpBlockID: nil,
                encryptedMetadata: nil,
                securityInfo: nil
            )
        }

        return VaultModelV1(
            schemaVersion: 1,
            createdAt: now,
            modifiedAt: now,
            entries: entries,
            folders: [],
            otpBlocks: [:]
        )
    }

    private func encrypt(_ text: String, key: ZeroizedData, now: Date) throws -> EncryptedField {
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: Data(text.utf8),
            vaultKey: key
        )
        return EncryptedField(bundle: bundle, createdAt: now, updatedAt: now)
    }

    func testSerializationSpeed() throws {
        let key = ZeroizedData(copying: Data(repeating: 0x22, count: 32))
        let vault = try makeLargeVault(count: 5_000, key: key)

        measure {
            _ = try? VaultSerialization.encode(model: vault, vaultKey: key)
        }
    }

    func testDeserializationSpeed() throws {
        let key = ZeroizedData(copying: Data(repeating: 0x22, count: 32))
        let vault = try makeLargeVault(count: 5_000, key: key)
        let encoded = try VaultSerialization.encode(model: vault, vaultKey: key)

        measure {
            _ = try? VaultSerialization.decode(from: encoded, vaultKey: key)
        }
    }
}

final class ZeroizedDataBenchmarks: XCTestCase {

    func testZeroizedDataAccess() throws {
        let secret = ZeroizedData(copying: Data(repeating: 0xAB, count: 64))

        measure {
            _ = try? secret.withBytes { buffer in
                return buffer.count
            }
        }
    }
}

final class VaultEncryptionBenchmarks: XCTestCase {

    func testEncryptionCost() throws {
        let key = ZeroizedData(copying: Data(repeating: 0x11, count: 32))
        let plaintext = Data(repeating: 0x55, count: 128)

        measure {
            _ = try? VaultEncryption.encryptEntry(
                plaintext: plaintext,
                vaultKey: key
            )
        }
    }

    func testDecryptionCost() throws {
        let key = ZeroizedData(copying: Data(repeating: 0x11, count: 32))
        let plaintext = Data(repeating: 0x55, count: 128)
        let cipher = try VaultEncryption.encryptEntry(
            plaintext: plaintext,
            vaultKey: key
        )

        measure {
            _ = try? VaultEncryption.decryptEntry(
                cipher,
                vaultKey: key
            )
        }
    }
}

final class PartialDecryptBenchmarks: XCTestCase {

    func testPartialPasswordDecryptSpeed() throws {
        let key = ZeroizedData(copying: Data(repeating: 0x55, count: 32))
        let now = Date()

        let encPass = try VaultEncryption.encryptEntry(
            plaintext: Data("VeryStrongPassword123!".utf8),
            vaultKey: key
        )

        let entry = VaultEntry(
            id: UUID(),
            title: "Example",
            domain: "a.com",
            createdAt: now,
            updatedAt: now,
            encryptedUsername: nilEncryptedField(now),
            encryptedPassword: EncryptedField(bundle: encPass, createdAt: now, updatedAt: now),
            encryptedNotes: nil,
            otpBlockID: nil,
            encryptedMetadata: nil,
            securityInfo: nil
        )

        measure {
            _ = try? entry.decryptPasswordOnly(vaultKey: key)
        }
    }

    private func nilEncryptedField(_ now: Date) -> EncryptedField {
        // A valid-but-empty placeholder for username tests.
        return EncryptedField(
            bundle: VaultCiphertext(
                ciphertext: Data("x".utf8),
                nonce: Data(repeating: 1, count: 12),
                associatedData: nil
            ),
            createdAt: now,
            updatedAt: now
        )
    }
}

final class OTPBenchmarks: XCTestCase {

    func testOTPCost() throws {
        let now = Date()

        // Vault key used for decrypting OTP secrets
        let key = ZeroizedData(copying: Data(repeating: 0xAB, count: 32))

        // Encrypt a real OTP secret ONCE to simulate real cost
        let secret = Data("JBSWY3DPEHPK3PXP".utf8)  // Base32("Hello!") example
        let encryptedField = try encryptSecret(secret, key: key)

        // Build 200 OTP blocks sharing the same encrypted secret
        let blocks = (0..<200).map { _ in
            OTPBlock(
                id: UUID(),
                algorithm: .sha1,
                digits: 6,
                period: 30,
                encryptedSecret: encryptedField,
                encryptedMetadata: nil
            )
        }

        // Benchmark OTP generation
        measure {
            for block in blocks {
                _ = try? block.generateOTP(at: now, vaultKey: key)
            }
        }
    }

    private func encryptSecret(
        _ plain: Data,
        key: ZeroizedData
    ) throws -> EncryptedField {
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: plain,
            vaultKey: key
        )
        return EncryptedField(bundle: bundle, createdAt: Date(), updatedAt: Date())
    }
}

