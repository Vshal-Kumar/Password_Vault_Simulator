"""Security tests: Plaintext inspection, audit log scrubbing, strength analysis, and generator."""

import json
from password_vault.vault.manager import VaultManager
from password_vault.security.validation import PasswordStrengthEvaluator, InputValidator
from password_vault.security.generator import PasswordGenerator
from password_vault.security.audit import AuditLogger


def test_plaintext_inspection_security(tmp_path):
    """
    CRITICAL SECURITY TEST:
    Verify that neither usernames nor passwords exist in plaintext
    inside the encrypted storage file on disk.
    """
    vault_file = tmp_path / "security_vault.enc"
    manager = VaultManager(vault_file)
    manager.create_vault("MasterVaultPassword123!")
    
    secret_user = "user123"
    secret_pass = "SuperSecretPassword987!"
    secret_notes = "Confidential server access tokens"
    
    manager.add(
        service="github",
        username=secret_user,
        password=secret_pass,
        notes=secret_notes,
    )
    
    # Read raw content of vault file
    with open(vault_file, "rb") as f:
        raw_bytes = f.read()
        raw_text = raw_bytes.decode("utf-8", errors="ignore")
    
    # Ensure plaintext secrets do NOT appear anywhere in the file
    assert secret_pass not in raw_text, "CRITICAL: Plaintext password found in vault file!"
    assert secret_user not in raw_text, "CRITICAL: Plaintext username found in vault file!"
    assert secret_notes not in raw_text, "CRITICAL: Plaintext notes found in vault file!"
    
    # Verify the file is valid JSON with only ciphertext
    parsed = json.loads(raw_text)
    assert "ciphertext" in parsed["vault"]
    assert isinstance(parsed["vault"]["ciphertext"], str)


def test_audit_log_scrubs_secrets(tmp_path):
    """Test that the audit log never contains plaintext passwords or secrets."""
    audit_file = tmp_path / "security_audit.log"
    logger = AuditLogger(audit_file)
    
    logger.log_event("TEST_EVENT", {
        "service": "github",
        "username": "user123",
        "password": "unmasked_secret_password!",
        "secret_token": "token_abc_123",
    })
    
    with open(audit_file, "r") as f:
        log_content = f.read()
        
    assert "unmasked_secret_password!" not in log_content
    assert "token_abc_123" not in log_content
    assert "[REDACTED]" in log_content


def test_password_strength_evaluator():
    """Test password strength evaluation logic and entropy calculation."""
    weak_res = PasswordStrengthEvaluator.evaluate("123456")
    assert weak_res["score"] < 30
    assert not weak_res["is_strong"]
    assert "easy to crack" in " ".join(weak_res["recommendations"])
    
    strong_res = PasswordStrengthEvaluator.evaluate("P@ssw0rd_Str0ng_99#Z!")
    assert strong_res["score"] >= 80
    assert strong_res["is_strong"]
    assert strong_res["entropy_bits"] > 60


def test_password_generator():
    """Test cryptographically secure password generator."""
    pwd = PasswordGenerator.generate(length=20, exclude_ambiguous=True)
    assert len(pwd) == 20
    
    # Check that ambiguous characters were excluded
    for c in ["0", "O", "1", "l", "I"]:
        assert c not in pwd
        
    eval_res = PasswordStrengthEvaluator.evaluate(pwd)
    assert eval_res["is_strong"]
