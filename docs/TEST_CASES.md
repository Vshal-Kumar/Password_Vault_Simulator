# Test Cases Specification

This document details the test cases implemented and verified in the **Secure Local Encrypted Password Vault Simulator**.

The test suite covers **Normal**, **Boundary**, **Invalid**, **Duplicate**, **Tampering**, **Rate-Limiting**, and **Plaintext Inspection** scenarios.

---

## Summary Table of Test Cases

| Test ID | Category | Scenario / Name | Input Description | Expected Behavior | Automated Test Location |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Normal | Create New Vault | Valid master password (`TestPassword123!`) | Vault file created on disk; session unlocked | `test_auth.py::test_create_vault_success` |
| **TC-02** | Invalid | Password Mismatch | Different confirm password | Raises `AuthenticationError`; no file written | `test_auth.py::test_create_vault_password_mismatch` |
| **TC-03** | Boundary | Short Master Password | 5-character password (`short`) | Rejection (`<8 characters`); vault not created | `test_auth.py::test_create_vault_password_too_short` |
| **TC-04** | Normal | Unlock with Correct Password | Valid master password | Authentication succeeds; vault unlocked | `test_auth.py::test_authentication_success_and_lock` |
| **TC-05** | Invalid | Unlock with Wrong Password | Incorrect master password | Authentication fails; vault remains locked | `test_auth.py::test_authentication_failure_wrong_password` |
| **TC-06** | Security | Rate Limiting Lockout | 5 consecutive failed attempts | Raises `RateLimitExceededError`; 30s lockout | `test_auth.py::test_rate_limiting_lockout_on_consecutive_failures` |
| **TC-07** | Normal | Add Credential (FR3) | `service="github"`, `user="user123"`, `pass="secret"` | Record encrypted and stored; password hidden | `test_vault.py::test_add_and_get_credential` |
| **TC-08** | Normal | Retrieve Masked Credential (FR5) | `GET github` | Returns `user123`, `Password: ********` | `test_vault.py::test_add_and_get_credential` |
| **TC-09** | Normal | Reveal Plaintext Password | `REVEAL github` + confirm `y` | Returns plaintext password `secret` | `test_vault.py::test_reveal_credential` |
| **TC-10** | Duplicate | Add Duplicate Service | Add `github` when `github` exists | Raises `DuplicateServiceError` ("Use UPDATE") | `test_vault.py::test_add_duplicate_service_fails` |
| **TC-11** | Invalid | Retrieve Nonexistent Service | `GET facebook` | Raises `ServiceNotFoundError` | `test_vault.py::test_get_nonexistent_service_fails` |
| **TC-12** | Normal | Update Existing Credential | `UPDATE github` -> new password | Record updated and re-encrypted | `test_vault.py::test_update_credential` |
| **TC-13** | Normal | Delete Credential | `DELETE github` + confirm `y` | Record permanently deleted from vault | `test_vault.py::test_delete_credential` |
| **TC-14** | Normal | List Services (FR4) | `LIST` with 3 services | Alphabetical listing; NO passwords displayed | `test_vault.py::test_list_services` |
| **TC-15** | Normal | Substring Search (FR8) | `SEARCH git` | Matches `github-work`, `gitlab-personal` | `test_vault.py::test_search_services` |
| **TC-16** | Security | Access Control on Locked Vault | Call CRUD operations when locked | Raises `VaultLockedError` ("Auth required") | `test_vault.py::test_locked_vault_blocks_operations` |
| **TC-17** | Security | Master Password Rotation | `change_master_password(new_pass)` | Re-encrypts under new key; old key invalidated | `test_vault.py::test_change_master_password` |
| **TC-18** | Security | Ciphertext Bit-Flip Tampering | Modify 1 bit of `vault.enc` | AEAD tag check fails -> `IntegrityError` | `test_crypto.py::test_aes_gcm_ciphertext_tampering_fails` |
| **TC-19** | Security | Salt Tampering Detection | Modify base64 salt in JSON | Key derivation mismatch -> `IntegrityError` | `test_storage.py::test_tampered_salt_detection` |
| **TC-20** | Normal | Vault Backup and Restore | `create_backup()`, restore | Corrupted vault restored successfully | `test_storage.py::test_backup_and_restore` |
| **TC-21** | Security | Plaintext Inspection Security | Read raw file bytes on disk | Asserts `secret` and `user123` NOT in plaintext | `test_security.py::test_plaintext_inspection_security` |
| **TC-22** | Security | Audit Log Secret Scrubbing | Log event with `"password"` | Sensitive keywords replaced with `[REDACTED]` | `test_security.py::test_audit_log_scrubs_secrets` |
| **TC-23** | Normal | Password Generator Entropy | Generate 20-char password | Guarantees entropy and diversity requirements | `test_security.py::test_password_generator` |
| **TC-24** | End-to-End | 12 Specification Test Cases | Full CLI execution sequence | All 12 project specification tests PASS | `test_e2e.py::test_specification_12_test_cases` |

---

## Verification Command

To execute all 34 test cases:
```bash
pytest -v tests/
```

**Result**: 34 passed in 4.87s (100% pass rate).
