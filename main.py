"""Main entry point for Secure Encrypted Password Vault Simulator."""

import argparse
import sys
from pathlib import Path

# Add project directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from password_vault.cli.interface import VaultCLI
from password_vault.config import DEFAULT_VAULT_PATH, DEFAULT_AUDIT_PATH


def parse_args():
    parser = argparse.ArgumentParser(
        description="Secure Local Encrypted Password Vault Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                           # Launch interactive CLI
  python main.py --vault-path ./my_vault.enc
  python main.py -c "ADD github user123 secret"
        """,
    )
    parser.add_argument(
        "--vault-path",
        type=Path,
        default=DEFAULT_VAULT_PATH,
        help="Path to the encrypted vault file (default: data/vault.enc)",
    )
    parser.add_argument(
        "--audit-path",
        type=Path,
        default=DEFAULT_AUDIT_PATH,
        help="Path to the security audit log file (default: data/vault_audit.log)",
    )
    parser.add_argument(
        "-c", "--command",
        type=str,
        default=None,
        help="Execute a single command string and exit",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    cli = VaultCLI(vault_path=args.vault_path, audit_path=args.audit_path)

    if args.command:
        cli.execute_command_string(args.command)
    else:
        cli.run_interactive()


if __name__ == "__main__":
    main()
