# Secure Local Encrypted Password Vault Simulator

---

## 1. Project Title
**Secure Local Encrypted Password Vault Simulator**  
*A Defensive Cybersecurity and Applied Cryptography System for Secure Offline Credential Management*

---

## 2. Problem Statement
In modern computing, users manage dozens of online accounts across different platforms. This leads to insecure practices such as:
- Reusing identical passwords across multiple services.
- Storing credentials in unencrypted text files (`passwords.txt`), sticky notes, or spreadsheets.
- Vulnerability to credential stuffing, unauthorized physical access, and offline data exfiltration attacks.

Standard naive storage solutions (such as storing passwords in plain JSON files) fail to provide **Confidentiality**, **Integrity**, or **Access Control**. If the storage file is stolen, all user accounts are immediately compromised.

---

## 3. Objective
The primary objective of this project is to design and develop an enterprise-grade, offline, local encrypted password vault simulator in Python that:
1. Protects stored service credentials against unauthorized disclosure using industry-standard **Authenticated Encryption (AES-256-GCM)**.
2. Derives strong cryptographic keys from a user-supplied Master Password using a memory-hard **Key Derivation Function (Argon2id)**.
3. Automatically detects any unauthorized tampering, bit-flipping, or file corruption through cryptographic authentication tags.
4. Enforces strict access control, credential masking, rate-limiting against brute-force attacks, and automatic in-memory zeroing upon session lock or exit.

---

## 4. Features

### Core Vault Operations (FR1 - FR10)
- **FR1 - Create Vault**: Initializes a new encrypted container protected by a Master Password with interactive password strength evaluation.
- **FR2 - Unlock Vault**: Authenticates the master password and derives the 256-bit AES key via Argon2id.
- **FR3 - Add Credential**: Securely encrypts and stores service credentials (`service`, `username`, `password`, `category`, `notes`). Passwords are never printed to stdout.
- **FR4 - List Services**: Lists all stored accounts with index numbers; passwords remain completely hidden.
- **FR5 - Retrieve Credential**: Displays account metadata with the password masked as `********`.
- **FR6 - Update Credential**: Modifies username, password, category, or notes for an existing account.
- **FR7 - Delete Credential**: Permanently removes an account with an interactive confirmation prompt.
- **FR8 - Search Services**: Substring keyword search across service names, usernames, and categories.
- **FR9 - Lock Vault**: Immediately wipes decrypted credentials and encryption keys from memory, requiring re-authentication.
- **FR10 - Exit**: Safely locks the vault, clears memory, and exits cleanly.

### Advanced Defensive Security Features
- **Explicit Password Reveal**: Plaintext password retrieval is segregated behind an explicit confirmation step (`REVEAL <service>` / Option 7).
- **Brute-Force Protection and Rate Limiting**: Lockout delay after 5 consecutive failed master password attempts.
- **Tamper Detection**: AEAD authentication tags detect any modification to the ciphertext or header metadata on disk.
- **High-Entropy Password Generator**: Cryptographically secure CSPRNG password generator with customizable length and ambiguity exclusion.
- **Password Strength Analyzer**: Real-time entropy calculator (in bits) and recommendation engine.
- **Zero-Trace Security Audit Log**: Records security events (`AUTH_SUCCESS`, `CREDENTIAL_ADDED`, `LOCKOUT`) while permanently scrubbing all passwords and secrets.
- **Master Password Key Rotation**: Allows re-encrypting the entire vault under a fresh Master Password and new salt.
- **Encrypted Backup and Restore**: Creates and restores verified backups of the encrypted vault container.

---

## 5. Technologies Used
- **Programming Language**: Python 3.10+ (Tested on Python 3.12.3)
- **Cryptography Engine**: `cryptography` (v50.0.0)
  - `Argon2id` (Password-Based Key Derivation with memory hardness)
  - `Scrypt` (Fallback Key Derivation Function)
  - `AESGCM` (AES-256-GCM Authenticated Encryption with Associated Data)
- **Random Number Generation**: `secrets` (Python Standard Library CSPRNG) and `os.urandom`
- **Testing Framework**: `pytest` (v9.1.1)
- **Data Persistence**: JSON serialization over encrypted binary payload with atomic file replacement
- **Cost**: **$0.00 (100% Free and Open-Source Tools)**

---

## 6. Installation / Setup Instructions

### Prerequisites
- Python 3.10 or higher installed on Linux, macOS, or Windows.
- Standard virtual environment (`venv`).

### Setup Commands
```bash
# 1. Navigate to the project directory
cd Password_Vault_Simulator

# 2. Activate virtual environment
source ../venv/bin/activate

# 3. Install required dependencies
pip install -r requirements.txt
```

---

## 7. How to Run the Project

### Interactive Mode (Recommended)
Launch the interactive terminal interface:
```bash
python main.py
```

### Command Line / Non-Interactive Mode
Execute single commands directly from the terminal:
```bash
# Add a credential directly
python main.py -c "ADD github user123 MySecretPassword123!"

# List all stored accounts
python main.py -c "LIST"

# Retrieve account info
python main.py -c "GET github"
```

### Custom Vault Path
```bash
python main.py --vault-path ./custom_vault.enc --audit-path ./custom_audit.log
```

---

## 8. Project Structure

```
Password_Vault_Simulator/
|-- main.py                     # Entry point and CLI dispatcher
|-- requirements.txt            # Python dependencies (cryptography, pytest)
|-- README.md                   # Comprehensive project documentation
|-- PROJECT_REPORT.md           # Formal academic/technical project report
|-- data/
|   |-- vault.enc               # Encrypted vault container (generated)
|   `-- vault_audit.log         # Security audit log without secrets (generated)
|-- docs/
|   |-- TEST_CASES.md           # Detailed test case specification and results
|   `-- DEMONSTRATION.md        # Step-by-step CLI demo transcripts and evidence
|-- password_vault/
|   |-- __init__.py
|   |-- config.py               # Constants, cryptographic parameters and custom exceptions
|   |-- crypto/
|   |   |-- __init__.py
|   |   |-- kdf.py              # Argon2id / Scrypt Key Derivation implementation
|   |   `-- encryption.py       # AES-256-GCM Authenticated Encryption engine
|   |-- vault/
|   |   |-- __init__.py
|   |   |-- models.py           # Credential and VaultPayload data models
|   |   |-- storage.py          # Atomic file I/O and encrypted envelope persistence
|   |   `-- manager.py          # CRUD coordinator and in-memory session manager
|   |-- auth/
|   |   |-- __init__.py
|   |   `-- authentication.py   # Rate-limiting, lockout, and session timeout
|   |-- security/
|   |   |-- __init__.py
|   |   |-- validation.py       # Password strength evaluator and input sanitizer
|   |   |-- generator.py        # CSPRNG secure password generator
|   |   `-- audit.py            # Secret-scrubbed security audit logger
|   `-- cli/
|       |-- __init__.py
|       `-- interface.py        # Clean interactive UI and command parser
`-- tests/
    |-- __init__.py
    |-- test_crypto.py          # KDF, cipher roundtrips, bit-flip detection (8 tests)
    |-- test_auth.py            # Authentication, mismatch, and lockout tests (6 tests)
    |-- test_vault.py           # CRUD operations, locked blocking, key rotation (10 tests)
    |-- test_storage.py         # File persistence, backup/restore, tampering (5 tests)
    |-- test_security.py        # Plaintext inspection and audit scrubbing (4 tests)
    `-- test_e2e.py             # 12 project specification test cases (1 comprehensive suite)
```

---

## 9. Testing Details

The project is backed by **34 automated pytest tests** covering 100% of core security, functional, and boundary requirements.

### Running the Tests
```bash
pytest -v tests/
```

### Summary of Test Suites:
| Test File | Description | Count | Result |
| :--- | :--- | :--- | :--- |
| `tests/test_crypto.py` | Validates KDF determinism, salt randomness, AES-GCM AEAD encryption/decryption, bit-flip tampering detection. | 8 | PASSED |
| `tests/test_auth.py` | Validates correct unlock, wrong password rejection, short password rejection, password mismatch, rate-limiting lockout. | 6 | PASSED |
| `tests/test_vault.py` | Validates Add, Get (masked), Reveal, Update, Delete, List, Search, Duplicate Rejection, Locked Vault enforcement, and Key Rotation. | 10 | PASSED |
| `tests/test_storage.py` | Validates JSON envelope integrity, corrupted ciphertext detection, corrupted salt detection, backup, and restore. | 5 | PASSED |
| `tests/test_security.py` | **Plaintext Inspection**: Verifies raw file bytes on disk contain ZERO plaintext usernames or passwords. Verifies audit log scrub. | 4 | PASSED |
| `tests/test_e2e.py` | End-to-end execution of all 12 specification test cases. | 1 | PASSED |
| **Total** | | **34** | **100% PASS** |

---

## 10. Limitations
1. **Single-User Local Architecture**: Designed for single-user desktop environments without cloud sync or multi-user access control lists (ACLs).
2. **OS Memory Swapping**: Python garbage collection does not allow guaranteed instantaneous zeroing of immutable `str` objects in virtual memory if the OS swaps pages to disk. (Mitigated by zeroing mutable buffers and using `bytes`/dataclass clear helpers).
3. **Clipboard Integration**: Clipboard auto-clearing depends on external OS clipboard daemons (`xclip`, `pbcopy`, or `pyperclip`), which vary across Linux desktop environments.

---

## 11. Future Improvements
1. **Hardware Security Key / FIDO2 / YubiKey Support**: Integrate WebAuthn/FIDO2 hardware tokens as a second-factor authentication mechanism for unlocking the vault.
2. **Secure Cross-Platform GUI / Web UI**: Build a modern desktop frontend (e.g., PyQt6 or Tauri) with automatic clipboard clearing timers.
3. **Encrypted Cloud Synchronization**: Implement end-to-end encrypted remote sync with WebDAV, Google Drive, or AWS S3.
4. **Password Breach Checking (HIBP API)**: Add k-Anonymity integration with the Have I Been Pwned API to check if user credentials have appeared in public data breaches.
5. **Secure Import/Export**: Support encrypted CSV/JSON imports and exports for migration from standard password managers (1Password, Bitwarden, KeePass).
