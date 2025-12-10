//
//  Step3-VaultManager
//  Entropy
//
//  Created by Khoa Phan (Home) on 12/10/25.
//

STEP 3 — VAULTMANAGER IMPLEMENTATION GUIDE
The Core Secure Engine

VaultManager is the authoritative controller for:
unlocking the vault
decrypting and managing in-memory structures
applying modifications (add, update, delete)
ensuring atomic, safe writes
handling fast unlock
handling autofill-safe decrypt paths
ensuring all invariants from Step 2 remain enforced
orchestrating OTP, scoring, metadata updates
wiping or creating vaults

This is the most security-critical layer in your entire app.
Mistakes here get people screwed in real life. We get this right.

MILESTONES
[] Milestone A — Vault File Management (Paths, Creation, Existence Checks)
[] Milestone B — Unlock Engine (Password → VaultKey → DecryptedVault)
[] Milestone C — Entry Lifecycle (Create, Update, Delete)
[] Milestone D — Folder Lifecycle (Create, Rename, Delete, Ordering)
[] Milestone E — OTP Handling Integration
[] Milestone F — Metadata & Security Scoring Pipeline
[] Milestone G — Atomic Save Pipeline (Full Vault Rewrite + Crash Safety)
[] Milestone H — Fast Unlock (Secure Enclave Integration)
[] Milestone I — Vault Wipe & Reset Engine
[] Milestone J — VaultManager Hardening & Integrity Enforcement
[] Milestone K — VaultManager Test Suite (Full Coverage)

✅ Milestone A — Vault File Management

Define the core filesystem API:
                                                        
Deliverables:
VaultFileLocator.swift
VaultFileIO.swift (safe read + write utilities)

Capabilities:
compute vault path (single vault for Step 3, multi-vault in Step 4)
check if vault exists
create empty vault (new user flow)
read raw vault file into memory
write vault atomically using a temp file + rename pattern

Requirements:
Never write partial vault files
Writes must be atomic (write to tmp → fsync → rename)
File permissions must be restricted (no world-read)
Must handle missing vault file gracefully (“fresh install”)

Tests:
vault path computed correctly
missing file handled without exception
atomic write prevents corruption when interrupted
vault read/write round trip identical

✅ Milestone B — Unlock Engine (Password → VaultKey → DecryptedVault)

This is the foundational API:
func unlockVault(password: ZeroizedData) throws -> DecryptedVault

Steps:
Derive vaultKey via Argon2id (using header.kdfParams)
Read + decode vault file (VaultSerialization.decodeVaultFile)
Validate header & ciphertext redundancy
Decrypt VaultModelV1 JSON using vaultKey
Deserialize into VaultModelV1
Map encrypted entries to DecryptedVaultEntry
Map folders
Build DecryptedVault struct

Requirements:
ZeroizedData for all decrypted fields
No password or key copies
Unlock must fail fast if header integrity mismatch
Must produce identical DecryptedVault for same ciphertext + key (deterministic)

Tests:
wrong password → fail
corrupted ciphertext → fail
valid vault → unlock succeeds
ZeroizedData wipes on deinit

✅ Milestone C — Entry Lifecycle (Add / Update / Delete)

APIs:
func addEntry(_ input: NewEntryData, into folderID: UUID?) throws -> UUID
func updateEntry(_ entryID: UUID, with changes: EntryUpdateData) throws
func deleteEntry(_ entryID: UUID) throws

Requirements:
Encrypt all modified fields using VaultEncryption.encryptEntry
Maintain createdAt, updatedAt timestamps
Maintain VaultEntryMetadata (lastViewed, lastCopied, etc.)
Automatically update passwordFingerprint when password changes
Maintain referential integrity with folders
After any modification, call save() (Milestone G)

Tests:
successfully add entry
update password only
update metadata only
update OTP reference
deletion removes from all folders
cannot delete non-existent entry
rejects invalid updates (e.g., invalid ciphertext)

✅ Milestone D — Folder Lifecycle

APIs:
func createFolder(named: String) throws -> UUID
func renameFolder(_ folderID: UUID, to newName: String) throws
func deleteFolder(_ folderID: UUID) throws
func reorderFolders(_ newOrder: [UUID]) throws

Requirements:
“Unfiled” folder must always exist
DeleteFolder moves entries to Unfiled, never deletes them
Folder ordering must always be sequential and stable
Prevent renaming to empty or duplicate names

Tests:
create folder
rename folder
delete folder moves entries safely
reorder operations behave deterministically

✅ Milestone E — OTP Handling Integration

OTP handling from Step 2 must now plug into VaultManager:

APIs:
attach OTP block to entry
update OTP metadata (lastUsed)
decrypt OTP secret for temporary usage
perform TOTP generation using VaultManager instead of directly calling OTPBlock

Requirements:
Zeroized secret decrypted only for the duration of OTP generation
lastUsed timestamp must be encrypted back into encryptedMetadata
OTP must respect entry locking logic (fail if vault is locked)

Tests:
OTP generation works for valid blocks
metadata updates persist
corrupted OTP block → fail
invalid digits/period/algorithm → reject

✅ Milestone F — Metadata & Security Scoring Pipeline

Using your Step 2 security scoring stubs:

Requirements:
Compute passwordFingerprint = SHA256(password) inside DecryptedVaultEntry
Detect reused passwords by comparing fingerprints
Compute entropyBits and score using PasswordStrengthEvaluator
Update VaultEntrySecurityInfo and re-encrypt it

Run scoring at:
unlock
entry creation
entry password change

Tests:
identical passwords produce identical fingerprints
reused passwords flagged
score updates correctly after password update
missing fingerprint allowed for older entries

✅ Milestone G — Atomic Save Pipeline

Saving is ALWAYS a full rewrite:
func saveVault(_ decrypted: DecryptedVault) throws

Pipeline:
Convert DecryptedVault → VaultModelV1
Serialize using VaultSerialization.encodeVaultFile
Atomic write to vault path
Update modifiedAt timestamp in header
Zeroize plaintext buffers

Requirements:
Must enforce deterministic field ordering
No incremental or partial writes
Never produce malformed files (use tmp-write rename pattern)
Ensure integrityHash stored in header is correct

Tests:
vault save/load round trip matches
tamper detection
simulated crash mid-save → old vault still intact
large vault save performance (5k entries)

✅ Milestone H — Fast Unlock (Secure Enclave)

Uses Step 1’s FastUnlockKeyManager.

Capabilities:
Store a wrapped vaultKey after first full unlock
Unlock with biometric → unwrap vaultKey
Perform partial unlock without Argon2id cost
Expire after N minutes of inactivity
Wipe if user disables biometrics

Tests:
fast unlock success
fast unlock fails when expired
fast unlock key wipe on logout
full unlock regenerates wrapped key

✅ Milestone I — Vault Wipe & Reset Engine

API:
func wipeVault() throws

Steps:
Delete vault file
Delete container metadata
Wipe fast-unlock key from Secure Enclave
Reset in-memory DecryptedVault
Force onboarding state

Requirements:
No decrypted data must survive beyond wipe
Wipe must be irreversible
On next launch, user must create new vault

Tests:
fresh state after wipe
attempted unlock after wipe → fails
wipe while unlocked → all ZeroizedData wiped

✅ Milestone J — VaultManager Hardening

Implement:
folder→entry reference validation
orphan detection
missing folder auto-recovery
timestamp validation
entry completeness checks
consistency checks on unlock and before save
prevent any plaintext from leaking into logs or errors

Tests:
orphan entry detected
missing folder detected
corrupted timestamps detected
malformed entries rejected

✅ Milestone K — VaultManager Test Suite (Full Coverage)

Test categories:

Unlock:
wrong password
corrupted header
truncated ciphertext
tampered model body

Entry & Folder Lifecycle:
add/update/delete entry
add/update/delete folder
reorder folders
metadata updates

OTP Integration:
generation
metadata updates
malformed OTPBlock

Saving:
save/load round trip
crash-safe save
corrupted save rejection

Wipe:
clean wipe
immediate re-init success

Fast Unlock:
unwrap success
unwrap fail on expiration

SUMMARY OF STEP 3 DELIVERABLES
VaultManager/
VaultManager.swift
VaultFileLocator.swift
VaultFileIO.swift
VaultUnlockEngine.swift
VaultSaveEngine.swift
VaultEntryCRUD.swift
VaultFolderCRUD.swift
VaultOTPService.swift
VaultSecurityScoringService.swift
VaultConsistencyChecker.swift
VaultWipeService.swift
FastUnlockIntegration.swift
                                                    
Tests/
UnlockTests
SaveTests
EntryLifecycleTests
FolderLifecycleTests
OTPTests
ScoringTests
IntegrityTests
WipeTests
FastUnlockTests
