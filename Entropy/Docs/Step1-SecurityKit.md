STEP 1 — SECURITYKIT IMPLEMENTATION GUIDE

• [DONE] Milestone A: SecureRandom + SecureCompare + tests
• [DONE] Milestone B: ZeroizedData + tests
• [DONE] Milestone C: AESGCM + tests (round-trip, nonce uniqueness, tamper)
• Milestone D: Argon2id + tests (vectors, params, errors)
• Milestone E: VaultKeyDerivation + tests (end-to-end)
• Milestone F: VaultEncryption + tests (per-entry, partial decrypt API surface)
• Milestone G: IntegrityChecks + tests (hashing, structure validation)
• Milestone H: Define Autofill interfaces (KDFCachePolicy, FastUnlockKeyManager, AESGCMContextPool, EncryptedPayload, AutofillEphemeralMemory) with basic tests/stubs to lock in boundaries

Foundations for world-class local-only cryptography in Entropy

SecurityKit is the cryptographic core of Entropy.
It isolates all encryption, key derivation, secure memory, comparisons, and integrity checks into one hardened, testable subsystem.
Nothing outside SecurityKit should ever deal with cryptographic primitives or decrypted secrets.

This document defines everything required to implement SecurityKit at an industry-leading level.

SECURITYKIT DIRECTORY STRUCTURE

SecurityKit/
Crypto/
Argon2.swift
AESGCM.swift
SecureRandom.swift
SecureCompare.swift
ZeroizedData.swift
VaultCore/
VaultKeyDerivation.swift
VaultEncryption.swift
IntegrityChecks.swift

CORE PRINCIPLES

• No decrypted secrets leave SecurityKit except inside a ZeroizedData container.
• AES-GCM must use a unique random nonce per encryption operation — never reused.
• Argon2id is the only allowed password-based key derivation function.
• All sensitive comparisons must use constant-time equality.
• All decrypted data must be wiped from memory as soon as possible.
• No SwiftUI, Combine, or view-model logic may appear inside SecurityKit.
• All failures must be explicit — never silently ignore crypto errors.
• Every component must be deterministic and unit-testable.

Additional core principles for future Autofill support:

• Secure Enclave–backed fast-unlock mode must be supported for the Autofill extension.
• No plaintext may be passed between app and extension — only encrypted payloads.
• Extension memory must be strictly scoped and automatically wiped on session end.
• Argon2 re-derivation must be minimized or avoided in extension contexts.
• Cryptographic operations inside the extension must be fast and avoid UI blocking.
• Partial field-level decryption (username only, password only) is mandatory for least-privilege access.

COMPONENT DETAILS

Below are the exact specifications for each part of SecurityKit.

1. Argon2.swift — Password Key Derivation
Purpose: Convert the user’s password into a hardened 32-byte master key.
Algorithm: Argon2id

Recommended defaults (2025 baseline):
• Memory: 64–128 MB
• Iterations: 2–3
• Parallelism: 2–4
• Salt length: 16–32 bytes
• Output key length: 32 bytes

Requirements:
• Always generate a new random salt when creating a vault.
• Never reuse salts or reduce Argon2 params.
• Enforce strong minimum password length.
• Derivation errors must throw, not fail silently.

Autofill additions:
• Argon2 execution must be bypassable via a Fast Unlock path using Secure Enclave.
• Implement KDFCachePolicy to allow short-lived caching of derived keys (10–20 seconds max) within extension contexts.
• All Argon2 operations in extension must occur off the main thread and respect strict timeouts.

2. AESGCM.swift — AES-256-GCM Encryption
Purpose: Encrypt all sensitive data including vault keys, passwords, and OTP secrets.

Requirements:
• AES-256-GCM only.
• Nonce must be 12 bytes, cryptographically random.
• Every encryption must use a brand new random nonce.
• Authentication tag must be validated on decrypt.
• Reject malformed or truncated ciphertext.

API:
• Encrypt returns ciphertext + nonce.
• Decrypt receives ciphertext + nonce and returns plaintext or throws.

GCM Security Notes:
• Reusing a nonce with the same key destroys security.
• Nonce generation must come from SecureRandom.
• All plaintext buffers must be wiped after encryption.

Autofill additions:
• AESGCMContextPool must support reusing AEAD contexts for faster extension decrypt operations.
• Encryption routines must support partial-field operations (decrypt only password, decrypt only username, decrypt only OTP).

3. SecureRandom.swift — Cryptographically Secure Randomness
Purpose: Provide secure randomness for salts, nonces, vault keys, and OTP seeds.

Requirements:
• Must use CryptoKit's SecRandomCopyBytes or SecureRandomNumberGenerator.
• No deterministic PRNG.
• Must fail loudly if randomness cannot be gathered.
• Must support generating large random byte buffers efficiently.

Autofill additions:
• Must support ephemeral random sources for extension (shorter memory lifetime).
• Extension-safe randomness must not persist across processes.

4. SecureCompare.swift — Constant-Time Equality

Purpose: Prevent timing attacks on secret values.

Requirements:
• Must iterate through all bytes before returning.
• Must not branch or return early.
• Used for comparing passwords, OTP secrets, vault keys, etc.
• Should operate on Data and raw byte buffers.

5. ZeroizedData.swift — Memory Wiping Container

Purpose: Store decrypted secrets safely in memory.

Requirements:
• Must zeroize internal memory on deinit.
• Must not allow implicit copying.
• Must provide controlled access via closures.
• Must not allow conversion to String.
• Must wipe memory even if an exception occurs.

Usage:
• Wrap decrypted passwords
• Wrap decrypted vault key
• Wrap decrypted OTP secret

Autofill additions:
• Must support “scope tokens” defining automatic wipe triggers:
    • wipe on extension session end
    • wipe after timeout
    • wipe when caller releases reference
    • wipe immediately after read
• Must support extremely short lifetimes (under 1 second) for quick lookups.

6. VaultKeyDerivation.swift — Full Key Pipeline

Purpose: Create and protect the vault encryption key.

Steps:
• Derive masterKey = Argon2id(password, KDFParams)
• Generate a new random 32-byte vaultKey
• Encrypt vaultKey with masterKey using AES-GCM
• Package values into a VaultKeyBundle for the vault file

Outputs include:
• KDFParams
• vaultKeyEncrypted
• vaultKeyNonce

Requirements:
• Never expose the raw vaultKey outside ZeroizedData.
• Must ensure safe parameter ranges for Argon2id.
• Must validate master password before decryption.

Autofill additions:
• Must support decryptVaultKeyWithSecureEnclave() for biometric fast unlock.
• Must produce optional “Fast Unlock Encrypted Vault Key” bound to device keypair.
• Must integrate with LocalAuthentication for faceID/TouchID unlock in extension.

7. VaultEncryption.swift — Entry Encryption and Decryption

Purpose: Encrypt and decrypt each vault entry (passwords, OTP secrets, future attachments).

Requirements:
• Each entry gets its own AES-GCM nonce.
• Nonce must be random and 12 bytes.
• Encrypt returns ciphertext + nonce.
• Decrypt must validate tag and throw errors.
• Must accept a vaultKey wrapped in ZeroizedData.

Usage:
• Encapsulates per-entry encryption logic.
• Ensures uniform encryption model across all entry fields.

Autofill additions:
• Must support partial decryption:

decryptUsernameField

decryptPasswordField

decryptOTPField
• Must be able to operate safely with extension-scoped vault keys.
8. IntegrityChecks.swift — Tamper Detection

• Purpose: Provide SHA256 integrity hashing and structure validation.

Requirements:
• SHA256(data) must return a hash used to verify vault structure.
• Should validate JSON structure before decrypting vault contents.
• Should detect:
    • Corrupt vault files
    • Mismatched vault versions
    • Rolled-back vaults
    • Wordlist tampering

Autofill additions:
• Must support verifying encrypted payloads exchanged between app and extension.
• Must reject payloads missing integrity metadata.

ADDITIONAL AUTO-FILL ONLY COMPONENTS
FastUnlockKeyManager.swift

• Stores a device-bound keypair (Secure Enclave).
• Encrypts vaultKey with public key.
• Decrypts vaultKey in extension via biometric authentication.

AutofillEphemeralMemory.swift

• Extremely short-lived memory container.
• Wipes content when Autofill session ends.
• Wipes content if extension is backgrounded or terminated.

EncryptedPayload.swift

• Used for secure IPC between main app and Autofill extension.
• Contains ciphertext, nonce, metadata.
• Never transports plaintext.

KDFCachePolicy.swift

• Allows temporary caching of Argon2-derived masterKey for 10–20 seconds max.
• Used only in extension for UX.
• Automatically wipes key after timeout or extension termination.

AESGCMContextPool.swift

• Speeds up repeated decrypt operations in the extension.
• Minimizes overhead from AEAD reinitialization.

AutofillEntry.swift

• Special minimized data model used only by extension.
• Contains decrypted password only, inside ZeroizedData.
• Does not contain full entry or extra fields.

PERFORMANCE REQUIREMENTS

• AES-GCM operations must minimize copies of Data.
• Argon2 worker threads should be reused when possible.

• Decrypt lazily:
Only decrypt password when user taps reveal.
Only decrypt OTP secret when computing OTP code.
Keep decrypted vault in memory only during unlock session.
Avoid re-encoding the vault unnecessarily (debounce writes).

HARDENING REQUIREMENTS

• Never store decrypted secrets in @State, @Published, or SwiftUI environment.
• Clipboard must auto-clear after configurable timeout.
• Vault must lock immediately when app enters background (configurable).
• Implement unlock rate-limiting with exponential backoff.
• Log only redacted or non-sensitive information.
• Never print keys, salts, nonces, or Data buffers in debug logs.

REQUIRED UNIT TESTS

• SecurityKit must include isolated tests for:
Argon2 correctness for known test vectors.
AES-GCM round-trip encryption/decryption.
Nonce uniqueness.
secureCompare constant-time behavior.
ZeroizedData memory wiping.
VaultKeyDerivation end-to-end correctness.
SHA256 hashing.
Malformed ciphertext rejection.

SUMMARY OF STEP 1 DELIVERABLES

SecurityKit must provide the following components:

Crypto:
Argon2.swift
AESGCM.swift
SecureRandom.swift
SecureCompare.swift
ZeroizedData.swift

VaultCore:
VaultKeyDerivation.swift
VaultEncryption.swift
IntegrityChecks.swift

SecurityKit becomes the only cryptographic dependency for the entire app.
All higher-level modules must consume SecurityKit without reimplementing cryptography.
