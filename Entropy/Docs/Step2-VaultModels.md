STEP 2 — VAULT MODELS IMPLEMENTATION GUIDE

MILESTONES:
[x] Milestone A — Vault File Header + Versioning
[x] Milestone B — VaultEntry + VaultEntryMetadata + EntryFieldTypes
[] Milestone C — VaultFolder Structure
[] Milestone D — OTPBlock Model
[] Milestone E — DecryptedVault + DecryptedVaultEntryåç
[] Milestone F — VaultSerialization (encode/decode)
[] Milestone G — VaultModelV1 (Full On-Disk Format)
[] Milestone H — VaultEntrySecurityInfo (Score)
[] Milestone I — Vault Model Hardening
[] Milestone J — VaultAutofillAdapter (Real Implementation)
[] Milestone K — VaultModel Benchmarks

(After completing Step 1: SecurityKit)

Step 2 defines the Vault Model Layer — the secure, encrypted, future-proof data structures for the entire password manager.

SecurityKit gives you the cryptographic foundation.
Step 2 gives you the vault file format, entry models, and the decrypted in-memory representation used by the app.

Vault Models form the contract between:
Local storage
VaultManager
Autofill
UI ViewModels
Migration systems

This step must be rock solid because versioning mistakes here cannot be undone after users store data.

VaultModels/
    VaultModelV1.swift
    VaultFolder.swift
    VaultEntry.swift
    VaultEntryMetadata.swift
    OTPBlock.swift
    DecryptedVault.swift
    DecryptedVaultEntry.swift
    VaultFileHeader.swift
    VaultSerialization.swift
    EntryFieldTypes.swift
    VaultEntrySecurityInfo.swift

CORE PRINCIPLES (Step 2)
🧱 Structural invariants

• Vault files are immutable snapshots — rewritten entirely on save.
• Every entry and folder has a stable UUID, not an index.
• The vault is a single encrypted blob, not scattered records.
• The encrypted vault data must be 100% deterministic given the same inputs.

🔐 Security invariants

• No decrypted values leave Vault Models except wrapped in ZeroizedData.
• Vault models never perform crypto directly — they use SecurityKit.
• Vault models must reject malformed, missing, truncated, or version-mismatched data.
• IntegrityChecks must verify structure before decrypting entries.
• Security score (Milestone M) must live in VaultEntrySecurityInfo.

🔄 Future-proofing

• Vault versions must support forward and backward compatibility.
• Migration logic (Step 3) will depend on this structure remaining stable.
• All fields must be Codable and version-tagged.

DEPENDENCIES FROM STEP 1

Step 2 consumes, but does not modify, these components:

Required SecurityKit components:
ZeroizedData (for decrypted fields)
AESGCM (VaultEncryption)
Argon2id (VaultKeyDerivation)
SecureRandom
IntegrityChecks
EncryptedPayload (Autofill)
AESGCMContextPool (Autofill extension)
FastUnlockKeyManager (Unlock flows)
ZeroizedData “scope” policies
PasswordStrengthEvaluator (Milestone M stub)

Everything in Step 2 is layered on top of Step 1.

✔️ Milestone A — Vault File Header + Versioning

Define:
VaultFileHeader
vaultVersion
schemaVersion
createdAt, modifiedAt
encryptionMethod (always AES-GCM)
kdfParams (Argon2 params used during creation)

Requirements:
• Codable and fixed layout
• Must include integrity hash placeholder
• Must validate version on load
• Must be tested against malformed headers, missing fields, zero-length data

Tests:
header round-trip
version mismatch
missing fields reject

✔️ Milestone B — VaultEntry + EntryFieldTypes

Define the encrypted model for each vault item:
VaultEntry
EntryFieldTypes
VaultEntryMetadata

VaultEntryMetadata
    Encrypted Codable struct containing:
        lastCopiedUsername: Date?
        lastCopiedPassword: Date?
        lastUsedOTP: Date?
        lastViewed: Date?

Each encrypted field contains:
VaultCiphertext
metadata (createdAt, updatedAt)
optional securityInfo reference

Fields inside VaultEntry:
    encrypted username
    encrypted password
    encrypted notes (optional)
    encrypted OTPBlock (via otpBlockID)
    encrypted metadata block (optional)
        stores usage-related timestamps:
            lastCopiedUsername
            lastCopiedPassword
            lastUsedOTP
            lastViewed

Requirements (updated):
    No decrypted fields in VaultEntry
    All sensitive fields, including metadata, encrypted independently
    UUID for entry
    Codable, fully versioned
    Compatible with partial decryption:
    decrypt username only
    decrypt password only
    decrypt OTP only
    decrypt metadata only ← NEW

Tests (updated):
    Entry encode/decode
    Missing ciphertext rejects
    Invalid nonce rejects
    Metadata encode/decode + corruption rejection
    Partial decrypt helpers work with mock VaultEncryption

✔️ Milestone C — VaultFolder Structure

Define:
VaultFolder
folderID: UUID
name: String
orderIndex: Int
entries: [UUID]

Requirements:

• Must not contain decrypted data
• Must be deterministic and Codable
• Guaranteed folder ordering
• Folder rename safe
• “Unfiled” folder must always exist

Tests:
add/remove entry
folder renaming
folder ordering

✔️ Milestone D — OTPBlock Model

Define:
type: TOTP
secret: VaultCiphertext
algorithm: SHA1/SHA256/SHA512
digits
period
lastUsed

Requirements:
• Must be fully encrypted
• Partial decrypt possible
• OTPBlock codable

Tests:
encode/decode
invalid algorithm reject
partial decrypt (with mock key)

✔️ Milestone E — DecryptedVault + DecryptedVaultEntry

Define the in-memory decrypted representation used by ViewModels.

DecryptedVault
vaultKey: ZeroizedData
entries: [DecryptedVaultEntry]
folders: [VaultFolder]
metadata: header fields
DecryptedVaultEntry
username: ZeroizedData
password: ZeroizedData
otpSecret: ZeroizedData?
notes: ZeroizedData?
securityInfo: VaultEntrySecurityInfo (score)
createdAt / updatedAt

Requirements:
• Every decrypted field must be ZeroizedData
• Must call ZeroizedData.wipe() on deinit
• Must not copy decrypted bytes
• Must only be produced through VaultManager.unlockVault() (Step 3)

Tests:
deinit wipe behavior
decoding with mock decrypt
decrypted structs hold correct data

✔️ Milestone F — VaultSerialization (encode/decode)

Includes:
JSON/Binary format

Structure:
VaultFileHeader
AES-GCM encrypted VaultModelV1 blob
IntegrityHash


Requirements:
• Encode entire vault deterministically
• Decode must validate structure BEFORE decrypting
• Reject:
    mismatched hash
    missing fields
    truncated ciphertext
    invalid version

Tests:
full encode/decode
tamper detection
hash mismatch
truncated ciphertext

✔️ Milestone G — VaultModelV1 (Full On-Disk Format)

Define:
full top-level structure containing:
    entries
    folders
    otp blocks
    global metadata
    createdAt / modifiedAt
    schemaVersion

Requirements:
• Codable, stable, documented
• Frozen layout (never change without migration path)

Tests:
load/save
schema version mismatch
empty vault creation

✔️ Milestone H — VaultEntrySecurityInfo (Score)

(Uses Milestone M stub until real evaluator exists)

Fields:
strength: PasswordStrength
score: Int?
entropyBits: Double?
lastEvaluated: Date
Password detection (for reused passwords)
passwordFingerprint: Data?
Encrypted SHA-256 hash of the decrypted password
Stored inside the vault, never plaintext
Used to efficiently detect reused passwords without decrypting the entire vault repeatedly
Computed only in VaultManager.unlockVault() during Milestone E
Optional for backward compatibility

🔐 Fingerprint Rules
Must be computed from decrypted password bytes inside DecryptedVaultEntry
Must use a strong, stable hash (SHA-256)
Must be stored encrypted along with other security info (AES-GCM inside VaultEntry)
Must never leave the vault or be exposed in plaintext form
May be empty (nil) for newly created entries until evaluation is run
Used in Vault Hardening (Milestone I) to detect:
duplicate passwords
reused passwords across folders
cross-entry security risks

Requirements:
• Must be Codable
• Must support default values when score not computed
• Struct must be fully Codable + Equatable + Sendable
• Must support default values for entries where scoring has not yet been evaluated
• Must deserialize correctly even when passwordFingerprint is missing (older vaults)
• Must be stable and version-safe (frozen layout after release)

Tests:
encode/decode round-trip
default initializer covers required fields
missing passwordFingerprint decodes successfully
passwordFingerprint persists correctly when present
two identical fingerprints detect reuse
different passwords produce different fingerprints

✔️ Milestone I — Vault Model Hardening

Implement:
ID uniqueness validation
Folder → entry references validation
Entry completeness checks
Field presence checks
Timestamp validation
Detect orphaned entries
Detect missing folders
Integrity hash verification (via IntegrityChecks)

Tests:
missing entry detection
orphaned folder entry
invalid UUID formats
hash mismatch

✔️ Milestone J — VaultAutofillAdapter (Real Implementation)

Uses Step 1’s placeholder.

Requirements:
• Convert VaultEntry → AutofillPasswordPayload
• Validate domain matching rules
• Partial decrypt password only
• Produce a valid payload with VaultEncryption
• Strict isolation: NO plaintext touches the main process except inside ZeroizedData

Tests:
payload generation
wrong domain reject
missing password reject
tamper detection

✔️ Milestone K — VaultModel Benchmarks (Optional but Recommended)

Benchmark:
serialization speed
memory usage
large vault (~5k entries)
partial decrypt performance
OTP generation cost

Ensure:
No unnecessary copies
ZeroizedData access is fast
VaultEncryption AES-GCM overhead is acceptable

REQUIRED TEST SUITE FOR STEP 2

You must provide tests for:
Vault Structure
    Encoding/decoding
    Version mismatch
    Missing fields
    Tampered data
VaultEntry
    Creation
    Partial decrypt
    Reject malformed ciphertext
Folders
    Add/remove/rename/order
    Orphan detection
OTPBlock
    Configuration validation
    Encrypt/decrypt flow
Decrypted Models
    Zeroize on deinit
    Correct mapping from encrypted to decrypted structures
Autofill
    payload creation
    metadata correctness
    notImplemented stub replaced with real implementation

SUMMARY OF STEP 2 DELIVERABLES

VaultModels/
VaultModelV1.swift
VaultFolder.swift
VaultEntry.swift
OTPBlock.swift
VaultFileHeader.swift
VaultSerialization.swift
DecryptedVault.swift
DecryptedVaultEntry.swift
EntryFieldTypes.swift
VaultEntrySecurityInfo.swift
VaultAutofillAdapter.swift (real implementation)
VaultModels must:

• Define the entire on-disk encrypted vault format
• Cleanly separate encrypted and decrypted models
• Enforce SecurityKit’s invariants
• Guarantee forward compatibility
• Provide all the structural components for VaultManager (Step 3)
