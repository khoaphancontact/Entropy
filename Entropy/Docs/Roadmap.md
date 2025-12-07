Step 0 — Cryptographic Policy
Define all allowed algorithms, key sizes, nonce requirements, and zeroization rules.
Ban unsafe primitives and establish sensitive-memory handling and key-lifetime policy.

Step 1 — SecurityKit (Cryptography Foundation)
Implement all cryptographic primitives: Argon2id, AES-256-GCM, secure random, constant-time compare, integrity checks, secure buffers, vault key derivation, vault entry encryption, and autofill-safe extension crypto.

Step 2 — Vault Models (Encrypted Storage Format)
Define the full encrypted vault file structure, folders, entries, OTP blocks, versioned Codable formats, headers, serialization, decrypted in-memory structures, and security scoring fields.

Step 3 — VaultManager (Core Secure Engine)
Implement loading, saving, unlocking, encrypting, decrypting, adding/removing folders, adding/updating entries, partial decryption, OTP handling, integrity verification, crash-safe persistence, and fast-unlock logic.

Step 4 — VaultContainerManager (Multi-Vault System)
Manage creation, listing, renaming, deleting, metadata, and sorting of multiple vault containers, including secure handling of VaultContainer.json.

Step 5 — Folder System (User Organization Layer)
Implement folder creation, deletion, renaming, ordering, and enforcement of stable folder IDs while preventing orphaned entries and guaranteeing an “Unfiled” fallback.

Step 6 — OTP Integration (TOTP Engine)
Implement encrypted TOTP secret storage, supported algorithms, digit ranges, period settings, otpauth:// URI parsing, Base32 validation, and controlled OTP generation with zeroized ephemeral memory.

Step 7 — Main App Views (UI Layer)
Build Home (entries, folders, security score), Generator (password/passphrase/entropy), and OTP Hub (secure OTP display).
Ensure ViewModels never hold long-lived decrypted secrets and use partial decryption only.

Step 8 — Migration System
Implement migration from older vault formats to the current version, including full decrypt → transform → re-encrypt logic and safe removal of deprecated formats.

Step 9 — Security Hardening
Add unlock rate-limiting, clipboard clearing, auto-locking, tamper detection, integrity verification, secure logging, sensitive wordlist integrity checks, and Secure Enclave–based anti-replay protections.

Step 10 — Documentation & Developer Tools
Produce complete documentation: Security Model, Vault Format Specification, API docs, ViewModel READMEs, lint rules, test vault generators, debugging utilities, and full performance benchmarks.
