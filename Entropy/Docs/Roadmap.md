HIGH-LEVEL ROADMAP FOR ENTROPY (ALL STEPS)

Step 1 — SecurityKit
Build the entire cryptography foundation.
Implement Argon2id, AES-GCM, secure random, constant-time compare, zeroized memory, vault key derivation, entry encryption, integrity checks, and autofill-safe extensions (fast unlock, ephemeral memory, encrypted payloads).
This step defines how all encryption, decryption, KDF logic, and secure memory handling works.

Step 2 — Vault Models
Define the full on-disk encrypted vault format and the in-memory decrypted structures.
Create VaultModel, VaultFolder, VaultEntry, OTPBlock, DecryptedVault, DecryptedVaultEntry.
Ensure models are versioned, Codable, future-proof, and aligned with entry-level encryption from Step 1.

Step 3 — VaultManager
Implement the core vault logic: create vaults, unlock vaults, save vaults, load vaults, add folders, rename folders, delete folders, add entries, update entries, attach OTP, remove OTP, generate OTP, partial decryption, integrity checks, and fast unlock support.
This becomes the “brain” for all secure storage operations.

Step 4 — VaultContainerManager (Multi-Vault Support)
Implement listing, creating, renaming, deleting, and storing metadata for multiple vaults.
Manage VaultContainer.json.
Link vault creation, unlocking, and deletion to VaultManager.

Step 5 — Folder System
Integrate folder creation, renaming, deletion, and ordering.
Support “Unfiled” folder.
Tie folders cleanly into entry models and VaultManager.

Step 6 — OTP Integration
Handle per-entry OTP secrets, encryption, decryption, and TOTP generation.
Support SHA1/SHA256/SHA512, 6–8 digits, custom periods.
Respect partial decryption and ZeroizedData rules.

Step 7 — Three Main App Views (Home, Generator, OTP Hub)
HomeView: vault entries, folders, security score, recommendations.
GeneratorView: password generator, passphrase generator, strength scoring.
OTPHubView: all OTPs across entries, secure display, partial decrypt on demand.
Each backed by clean ViewModels using VaultManager only.

Step 8 — Migration System
Create migration logic to convert your old vault format into the new version.
Decrypt old vault, re-map entries, create folders, re-encrypt entries with new format, generate new vaultKey, store properly, and remove deprecated data.

Step 9 — Security Hardening
Implement unlock rate limiting, clipboard clearing, background auto-lock, integrity checks, tamper detection, wordlist integrity verification, secure logging, and binding extension unlocks to Secure Enclave.

Step 10 — Documentation and Developer Tools
Produce full documentation: Security Model, Vault Format, API specs, View READMEs.
Generate utility scripts, linting rules, debugging toggles, and test harnesses for vaults, encryption, and performance.
