# Deliverable 3: Test Cases Specification

**Project**: Secure Local Encrypted Password Vault Simulator  
**Total Test Cases Implemented**: 34 automated tests  
**Testing Framework**: pytest (Python 3.12)  
**Test Pass Rate**: 100% (34 passed, 0 failed)

---

## 1. Summary Table of Test Cases

The test suite covers **Normal Inputs**, **Boundary Conditions**, **Invalid Inputs**, **Duplicate Scenarios**, **Tampering / Security Tests**, and **Plaintext Inspection**.

| Test ID | Category | Scenario / Name | Input Description | Expected Behavior | Automated Test Location |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Normal | Create New Vault (FR1) | Valid master password (`TestPassword123!`) | Vault file created on disk; session unlocked | `tests/test_auth.py::test_create_vault_success` |
| **TC-02** | Invalid | Password Mismatch | Different confirm password | Raises `AuthenticationError`; no file written | `tests/test_auth.py::test_create_vault_password_mismatch` |
| **TC-03** | Boundary | Short Master Password | 5-character password (`short`) | Rejection (`<8 characters`); vault not created | `tests/test_auth.py::test_create_vault_password_too_short` |
| **TC-04** | Normal | Unlock with Correct Password (FR2) | Valid master password | Authentication succeeds; vault unlocked | `tests/test_auth.py::test_authentication_success_and_lock` |
| **TC-05** | Invalid | Unlock with Wrong Password | Incorrect master password | Authentication fails; vault remains locked | `tests/test_auth.py::test_authentication_failure_wrong_password` |
| **TC-06** | Security | Rate Limiting Lockout | 5 consecutive failed attempts | Raises `RateLimitExceededError`; 30s lockout | `tests/test_auth.py::test_rate_limiting_lockout_on_consecutive_failures` |
| **TC-07** | Normal | Add Credential (FR3) | `service="github"`, `user="user123"`, `pass="secret"` | Record encrypted and stored; password hidden | `tests/test_vault.py::test_add_and_get_credential` |
| **TC-08** | Normal | Retrieve Masked Credential (FR5) | `GET github` | Returns `user123`, `Password: ********` | `tests/test_vault.py::test_add_and_get_credential` |
| **TC-09** | Normal | Reveal Plaintext Password | `REVEAL github` + confirm `y` | Returns plaintext password `secret` | `tests/test_vault.py::test_reveal_credential` |
| **TC-10** | Duplicate | Add Duplicate Service | Add `github` when `github` exists | Raises `DuplicateServiceError` ("Use UPDATE") | `tests/test_vault.py::test_add_duplicate_service_fails` |
| **TC-11** | Invalid | Retrieve Nonexistent Service | `GET facebook` | Raises `ServiceNotFoundError` | `tests/test_vault.py::test_get_nonexistent_service_fails` |
| **TC-12** | Normal | Update Existing Credential (FR6) | `UPDATE github` -> new password | Record updated and re-encrypted | `tests/test_vault.py::test_update_credential` |
| **TC-13** | Normal | Delete Credential (FR7) | `DELETE github` + confirm `y` | Record permanently deleted from vault | `tests/test_vault.py::test_delete_credential` |
| **TC-14** | Normal | List Services (FR4) | `LIST` with 3 services | Alphabetical listing; NO passwords displayed | `tests/test_vault.py::test_list_services` |
| **TC-15** | Normal | Substring Search (FR8) | `SEARCH git` | Matches `github-work`, `gitlab-personal` | `tests/test_vault.py::test_search_services` |
| **TC-16** | Security | Access Control on Locked Vault (FR9) | Call CRUD operations when locked | Raises `VaultLockedError` ("Auth required") | `tests/test_vault.py::test_locked_vault_blocks_operations` |
| **TC-17** | Security | Master Password Key Rotation | `change_master_password(new_pass)` | Re-encrypts under new key; old key invalidated | `tests/test_vault.py::test_change_master_password` |
| **TC-18** | Security | Ciphertext Bit-Flip Tampering | Modify 1 bit of `vault.enc` | AEAD tag check fails -> `IntegrityError` | `tests/test_crypto.py::test_aes_gcm_ciphertext_tampering_fails` |
| **TC-19** | Security | Salt Tampering Detection | Modify base64 salt in JSON | Key derivation mismatch -> `IntegrityError` | `tests/test_storage.py::test_tampered_salt_detection` |
| **TC-20** | Normal | Vault Backup and Restore | `create_backup()`, restore | Corrupted vault restored successfully | `tests/test_storage.py::test_backup_and_restore` |
| **TC-21** | Security | Plaintext Inspection Security | Read raw file bytes on disk | Asserts `secret` and `user123` NOT in plaintext | `tests/test_security.py::test_plaintext_inspection_security` |
| **TC-22** | Security | Audit Log Secret Scrubbing | Log event with `"password"` | Sensitive keywords replaced with `[REDACTED]` | `tests/test_security.py::test_audit_log_scrubs_secrets` |
| **TC-23** | Normal | Password Generator Entropy | Generate 20-char password | Guarantees entropy and diversity requirements | `tests/test_security.py::test_password_generator` |
| **TC-24** | End-to-End | 12 Specification Test Cases | Full CLI execution sequence | All 12 project specification tests PASS | `tests/test_e2e.py::test_specification_12_test_cases` |

---

## 2. Detailed Test Scenarios & Execution Proof

### 2.1 Test Case 1: Normal Scenario - Add Credential (`ADD github user123 secret`)
- **Input**: Service = `github`, Username = `user123`, Password = `secret`
- **Output**: `Credential stored successfully.` (Password is never printed).
- **Disk State**: Verified that neither `user123` nor `secret` exists in plaintext inside `data/vault.enc`.

### 2.2 Test Case 2: Boundary Scenario - Short Master Password
- **Input**: Master Password = `short` (5 characters)
- **Output**: `Error: Master password must be at least 8 characters long.`
- **Result**: Rejected without creating unencrypted files.

### 2.3 Test Case 3: Duplicate Scenario - Duplicate Service Rejection
- **Input**: Add `github` when `github` is already stored.
- **Output**: `Error: Service 'github' already exists. Use UPDATE instead.`
- **Result**: Prevents accidental overwriting.

### 2.4 Test Case 4: Invalid Scenario - Incorrect Master Password Authentication
- **Input**: Correct password = `MasterPassword123!`, Entered = `WrongPassword`
- **Output**: `Authentication failed. Vault remains locked.`
- **Result**: Authentication tag mismatch in AES-GCM prevents decryption.

### 2.5 Test Case 5: Security Scenario - Ciphertext Tampering Detection
- **Input**: A single byte in `data/vault.enc` ciphertext is modified on disk.
- **Output**: `Vault integrity verification failed! Ciphertext is corrupted or tampered with.`
- **Result**: AES-256-GCM AEAD authentication tag check immediately rejects modified files.

---

## 3. How to Run the Automated Test Suite

Run the following command from the project root:
```bash
pytest -v tests/
```

### Execution Output:
```text
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0
collected 34 items

tests/test_auth.py::test_create_vault_success PASSED
tests/test_auth.py::test_create_vault_password_mismatch PASSED
tests/test_auth.py::test_create_vault_password_too_short PASSED
tests/test_auth.py::test_authentication_success_and_lock PASSED
tests/test_auth.py::test_authentication_failure_wrong_password PASSED
tests/test_auth.py::test_rate_limiting_lockout_on_consecutive_failures PASSED
tests/test_crypto.py::test_salt_generation PASSED
tests/test_crypto.py::test_argon2id_key_derivation_determinism PASSED
tests/test_crypto.py::test_argon2id_key_derivation_different_inputs PASSED
tests/test_crypto.py::test_scrypt_key_derivation PASSED
tests/test_crypto.py::test_aes_gcm_encrypt_decrypt_roundtrip PASSED
tests/test_crypto.py::test_aes_gcm_wrong_key_fails PASSED
tests/test_crypto.py::test_aes_gcm_ciphertext_tampering_fails PASSED
tests/test_crypto.py::test_aes_gcm_associated_data_tampering_fails PASSED
tests/test_e2e.py::test_specification_12_test_cases PASSED
tests/test_security.py::test_plaintext_inspection_security PASSED
tests/test_security.py::test_audit_log_scrubs_secrets PASSED
tests/test_security.py::test_password_strength_evaluator PASSED
tests/test_security.py::test_password_generator PASSED
tests/test_storage.py::test_storage_initialization_creates_file PASSED
tests/test_storage.py::test_storage_save_and_load_roundtrip PASSED
tests/test_storage.py::test_tampered_ciphertext_detection PASSED
tests/test_storage.py::test_tampered_salt_detection PASSED
tests/test_storage.py::test_backup_and_restore PASSED
tests/test_vault.py::test_add_and_get_credential PASSED
tests/test_vault.py::test_reveal_credential PASSED
tests/test_vault.py::test_add_duplicate_service_fails PASSED
tests/test_vault.py::test_get_nonexistent_service_fails PASSED
tests/test_vault.py::test_update_credential PASSED
tests/test_vault.py::test_delete_credential PASSED
tests/test_vault.py::test_list_services PASSED
tests/test_vault.py::test_search_services PASSED
tests/test_vault.py::test_locked_vault_blocks_operations PASSED
tests/test_vault.py::test_change_master_password PASSED

============================== 34 passed in 5.19s ==============================
```
