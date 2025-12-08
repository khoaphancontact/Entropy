//
//  Test-OTPBlock.swift
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/8/25.
//

//
//  OTPBlockTests.swift
//  EntropyVaultModelsTests
//

import XCTest
@testable import Entropy

final class OTPBlockTests: XCTestCase {

    // MARK: - Helpers

    private func makeKey() -> ZeroizedData {
        ZeroizedData(copying: Data(repeating: 0x33, count: 32))
    }

    private func enc(
        _ string: String,
        key: ZeroizedData,
        date: Date
    ) throws -> EncryptedField {
        let bundle = try VaultEncryption.encryptEntry(
            plaintext: Data(string.utf8),
            vaultKey: key
        )
        return EncryptedField(bundle: bundle, createdAt: date, updatedAt: date)
    }

    private func makeBlock() throws -> (OTPBlock, ZeroizedData, Date, String) {
        let key = makeKey()
        let secret = "JBSWY3DPEHPK3PXP"   // Base32 example
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        let encSecret = try enc(secret, key: key, date: now)

        let metadata = OTPMetadata(lastUsed: now)
        let encMeta = try OTPMetadata.encrypt(metadata, vaultKey: key, now: now)

        let block = OTPBlock(
            algorithm: .sha1,
            digits: 6,
            period: 30,
            encryptedSecret: encSecret,
            encryptedMetadata: encMeta
        )

        return (block, key, now, secret)
    }


    // MARK: - Encode/Decode

    func testEncodeDecodeRoundTrip() throws {
        let (block, _, _, _) = try makeBlock()

        let data = try JSONEncoder().encode(block)
        let decoded = try JSONDecoder().decode(OTPBlock.self, from: data)

        XCTAssertEqual(decoded.algorithm, block.algorithm)
        XCTAssertEqual(decoded.digits, block.digits)
        XCTAssertEqual(decoded.period, block.period)
        XCTAssertEqual(decoded.encryptedSecret.bundle.ciphertext.count,
                       block.encryptedSecret.bundle.ciphertext.count)
    }


    // MARK: - Validation

    func testInvalidAlgorithmRejects() throws {
        let (block, key, now, secret) = try makeBlock()

        // Hack: Create invalid algorithm by re-encoding manually
        let bad = OTPBlock(
            id: block.id,
            algorithm: .sha1,    // We'll mutate after encoding
            digits: 6,
            period: 30,
            encryptedSecret: block.encryptedSecret
        )

        // Create invalid digits
        let invalid = OTPBlock(
            id: block.id,
            algorithm: .sha1,
            digits: 1,
            period: 30,
            encryptedSecret: block.encryptedSecret
        )

        XCTAssertThrowsError(try invalid.validate()) { error in
            XCTAssertEqual(error as? OTPBlockError, .invalidDigits)
        }
    }

    func testInvalidNonceFails() throws {
        let (block, _, _, _) = try makeBlock()

        let badNonce = Data(repeating: 0x00, count: 8) // invalid for AES-GCM
        let corruptedBundle = VaultCiphertext(
            ciphertext: block.encryptedSecret.bundle.ciphertext,
            nonce: badNonce,
            associatedData: block.encryptedSecret.bundle.associatedData
        )

        let corruptedField = EncryptedField(
            bundle: corruptedBundle,
            createdAt: block.encryptedSecret.createdAt,
            updatedAt: block.encryptedSecret.updatedAt
        )

        let badBlock = OTPBlock(
            id: block.id,
            algorithm: block.algorithm,
            digits: block.digits,
            period: block.period,
            encryptedSecret: corruptedField
        )

        XCTAssertThrowsError(try badBlock.validate()) { error in
            XCTAssertEqual(error as? OTPBlockError, .invalidCiphertext)
        }
    }

    // MARK: - Partial Decrypt

    func testDecryptSecret() throws {
        let (block, key, _, secret) = try makeBlock()

        let z = try block.decryptSecret(vaultKey: key)
        let decrypted = String(data: try z.withBytes { Data($0) }, encoding: .utf8)

        XCTAssertEqual(decrypted, secret)
    }

    // MARK: - Metadata

    func testMetadataDecrypt() throws {
        let (block, key, now, _) = try makeBlock()

        let meta = try block.decryptMetadata(vaultKey: key)
        XCTAssertNotNil(meta)
        XCTAssertEqual(meta?.lastUsed, now)
    }

    func testMetadataCorruptionFails() throws {
        let (block, key, _, _) = try makeBlock()

        guard let metaField = block.encryptedMetadata else {
            XCTFail("missing metadata"); return
        }

        var corrupted = metaField.bundle
        var bytes = corrupted.ciphertext
        bytes[0] ^= 0xFF
        corrupted = VaultCiphertext(
            ciphertext: bytes,
            nonce: corrupted.nonce,
            associatedData: corrupted.associatedData
        )

        let corruptField = EncryptedField(
            bundle: corrupted,
            createdAt: metaField.createdAt,
            updatedAt: metaField.updatedAt
        )

        let badBlock = OTPBlock(
            algorithm: block.algorithm,
            digits: block.digits,
            period: block.period,
            encryptedSecret: block.encryptedSecret,
            encryptedMetadata: corruptField
        )

        XCTAssertThrowsError(try badBlock.decryptMetadata(vaultKey: key)) { error in
            XCTAssertEqual(error as? OTPBlockError, .metadataDecodeFailed)
        }
    }
}
