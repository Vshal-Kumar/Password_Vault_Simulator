"""End-to-End tests verifying all 12 test cases from the specification."""

import io
import json
import base64
import pytest
from password_vault.cli.interface import VaultCLI


@pytest.fixture
def cli_instance(tmp_path, monkeypatch):
    """Fixture providing a fresh VaultCLI instance with captured stdout."""
    vault_file = tmp_path / "e2e_vault.enc"
    audit_file = tmp_path / "e2e_audit.log"
    cli = VaultCLI(vault_path=vault_file, audit_path=audit_file)
    return cli, vault_file


def run_cli_command(cli, cmd_str, monkeypatch, inputs=None):
    """Helper to execute CLI command and capture output."""
    output_buffer = io.StringIO()
    monkeypatch.setattr("sys.stdout", output_buffer)
    
    if inputs:
        input_iter = iter(inputs)
        monkeypatch.setattr("builtins.input", lambda prompt="": next(input_iter))
        monkeypatch.setattr("getpass.getpass", lambda prompt="": next(input_iter))
        
    cli.execute_command_string(cmd_str)
    return output_buffer.getvalue()


def test_specification_12_test_cases(cli_instance, monkeypatch):
    """
    Comprehensive test executing all 12 test cases specified in the project requirements.
    """
    cli, vault_file = cli_instance
    master_password = "TestPassword123!"

    # ==========================================
    # TEST 1 — CREATE VAULT
    # ==========================================
    out = run_cli_command(cli, "CREATE", monkeypatch, inputs=[master_password, master_password])
    assert "Vault created successfully" in out
    assert vault_file.exists()

    # Lock vault for authentication testing
    run_cli_command(cli, "LOCK", monkeypatch)
    assert not cli.manager.is_unlocked

    # ==========================================
    # TEST 3 — INCORRECT AUTHENTICATION
    # ==========================================
    out = run_cli_command(cli, "UNLOCK", monkeypatch, inputs=["WrongPassword"])
    assert "Authentication failed" in out
    assert "Vault remains locked" in out
    assert not cli.manager.is_unlocked

    # ==========================================
    # TEST 2 — CORRECT AUTHENTICATION
    # ==========================================
    out = run_cli_command(cli, "UNLOCK", monkeypatch, inputs=[master_password])
    assert "Authentication successful" in out
    assert "Vault unlocked" in out
    assert cli.manager.is_unlocked

    # ==========================================
    # TEST 4 — ADD CREDENTIAL ("ADD github user123 secret")
    # ==========================================
    out = run_cli_command(cli, "ADD github user123 secret", monkeypatch)
    assert "Credential stored successfully" in out
    assert "secret" not in out  # Password must NEVER appear in output

    # ==========================================
    # TEST 5 — LIST CREDENTIAL
    # ==========================================
    out = run_cli_command(cli, "LIST", monkeypatch)
    assert "github" in out
    assert "user123" not in out
    assert "secret" not in out

    # ==========================================
    # TEST 6 — RETRIEVE CREDENTIAL ("GET github")
    # ==========================================
    out = run_cli_command(cli, "GET github", monkeypatch)
    assert "Service: github" in out
    assert "Username: user123" in out
    assert "Password: ********" in out
    assert "secret" not in out

    # ==========================================
    # TEST 9 — DUPLICATE CREDENTIAL
    # ==========================================
    out = run_cli_command(cli, "ADD github user2 anothersecret", monkeypatch)
    assert "already exists" in out
    assert "Use UPDATE instead" in out

    # ==========================================
    # TEST 10 — UNKNOWN SERVICE ("GET facebook")
    # ==========================================
    out = run_cli_command(cli, "GET facebook", monkeypatch)
    assert "Credential not found" in out

    # ==========================================
    # TEST 7 — UPDATE CREDENTIAL ("UPDATE github")
    # ==========================================
    # inputs: username (blank to keep user123), new password: "newsecret", category, notes
    out = run_cli_command(cli, "UPDATE github", monkeypatch, inputs=["", "newsecret", "", ""])
    assert "Credential updated successfully" in out

    # Verify via reveal
    out = run_cli_command(cli, "REVEAL github", monkeypatch, inputs=["y"])
    assert "Password for github: newsecret" in out

    # ==========================================
    # TEST 8 — DELETE CREDENTIAL ("DELETE github")
    # ==========================================
    out = run_cli_command(cli, "DELETE github", monkeypatch, inputs=["y"])
    assert "Credential deleted" in out

    # Confirm it is no longer retrievable
    out = run_cli_command(cli, "GET github", monkeypatch)
    assert "Credential not found" in out

    # ==========================================
    # TEST 11 — LOCKED VAULT
    # ==========================================
    # Add back a credential, then lock
    run_cli_command(cli, "ADD github user123 secret", monkeypatch)
    out = run_cli_command(cli, "LOCK", monkeypatch)
    assert "Vault locked" in out
    assert not cli.manager.is_unlocked

    # Attempt GET while locked
    out = run_cli_command(cli, "GET github", monkeypatch)
    assert "Vault is locked" in out
    assert "Authentication required" in out

    # ==========================================
    # TEST 12 — VAULT TAMPERING
    # ==========================================
    # Manually tamper with the encrypted file
    with open(vault_file, "r") as f:
        data = json.load(f)
    
    # Flip bytes in ciphertext
    raw_ct = base64.b64decode(data["vault"]["ciphertext"])
    tampered_ct = bytearray(raw_ct)
    tampered_ct[3] ^= 0xAA
    data["vault"]["ciphertext"] = base64.b64encode(bytes(tampered_ct)).decode("ascii")
    
    with open(vault_file, "w") as f:
        json.dump(data, f)

    # Attempt unlock on tampered vault
    out = run_cli_command(cli, "UNLOCK", monkeypatch, inputs=[master_password])
    assert "Authentication failed" in out
    assert "Vault remains locked" in out
    assert not cli.manager.is_unlocked
