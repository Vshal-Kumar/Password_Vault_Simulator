"""Command-Line Interface for the Secure Password Vault Simulator."""

import getpass
import sys
import shlex
from pathlib import Path
from typing import Optional, List

from ..config import (
    DEFAULT_VAULT_PATH,
    VaultSecurityException,
    AuthenticationError,
    VaultLockedError,
    VaultAlreadyExistsError,
    VaultNotFoundError,
    DuplicateServiceError,
    ServiceNotFoundError,
    RateLimitExceededError,
)
from ..vault.manager import VaultManager
from ..auth.authentication import Authenticator
from ..security.validation import PasswordStrengthEvaluator, InputValidator
from ..security.generator import PasswordGenerator
from ..security.audit import AuditLogger


class VaultCLI:
    """Provides a professional interactive menu and direct command processor."""

    def __init__(self, vault_path: Optional[Path] = None, audit_path: Optional[Path] = None):
        self.vault_path = Path(vault_path) if vault_path else DEFAULT_VAULT_PATH
        self.manager = VaultManager(self.vault_path)
        self.audit = AuditLogger(audit_path)
        self.auth = Authenticator(self.manager, self.audit)
        self.running = True

    def print_banner(self) -> None:
        """Print application header banner."""
        print("=" * 52)
        print("     SECURE ENCRYPTED PASSWORD VAULT SIMULATOR      ")
        print("=" * 52)

    def print_main_menu(self) -> None:
        """Display the main menu based on current vault state."""
        if not self.manager.is_unlocked:
            print("\n" + "=" * 48)
            print("        SECURE PASSWORD VAULT (LOCKED)          ")
            print("=" * 48)
            print("  [1] Unlock Vault (Log in with Master Password)")
            print("  [2] Create a New Vault")
            print("  [3] Generate a Strong Random Password")
            print("  [4] Exit")
            print("-" * 48)
        else:
            print("\n" + "=" * 52)
            print("       SECURE PASSWORD VAULT (UNLOCKED)         ")
            print("=" * 52)
            print("  [1] Add New Account")
            print("  [2] Show Account Details (Username & Password)")
            print("  [3] List All Stored Accounts")
            print("  [4] Update Existing Account")
            print("  [5] Delete Account")
            print("  [6] Search Accounts")
            print("  [7] Reveal Plaintext Password (Explicit)")
            print("  [8] Generate Strong Password")
            print("  [9] Change Master Password")
            print(" [10] Security Audit History")
            print(" [11] Backup Vault File")
            print(" [12] Lock Vault")
            print(" [13] Exit")
            print("-" * 52)

    def _display_accounts_summary(self) -> List[str]:
        """Show current stored accounts with numbers for convenient selection."""
        services = self.manager.list_services()
        if services:
            print("\nStored Accounts:")
            for idx, svc in enumerate(services, start=1):
                try:
                    cred = self.manager.get(svc)
                    print(f"  [{idx}] {svc} (User: {cred['username']})")
                except Exception:
                    print(f"  [{idx}] {svc}")
            print()
        return services

    def _resolve_service_name(self, input_val: str) -> str:
        """Resolve user input to service name (supports exact name or list index number)."""
        input_clean = input_val.strip()
        if not input_clean:
            return input_clean

        # If it's already an exact match in the vault, return it
        try:
            self.manager.get(input_clean)
            return input_clean
        except (ServiceNotFoundError, VaultLockedError):
            pass

        # If it is a number, map to list index
        if input_clean.isdigit():
            idx = int(input_clean)
            services = self.manager.list_services()
            if 1 <= idx <= len(services):
                return services[idx - 1]

        return input_clean

    def handle_create_vault(self) -> None:
        """FR1: Create a new encrypted vault."""
        print("\nCREATE A NEW ENCRYPTED VAULT")
        print("-" * 40)
        if self.manager.is_initialized:
            print("Warning: A vault already exists at this location.")
            confirm = input("Are you sure you want to overwrite it? (All existing data will be lost!) [y/N]: ").strip().lower()
            if confirm != "y":
                print("Vault creation cancelled.")
                return

        print("Please choose a strong Master Password to protect your vault.")
        master_pass = getpass.getpass("Enter master password: ")
        if not master_pass:
            print("Error: Master password cannot be empty.")
            return

        # Show strength evaluation
        eval_result = PasswordStrengthEvaluator.evaluate(master_pass)
        print(f"\nPassword Strength: {eval_result['label']} (Score: {eval_result['score']}/100, Entropy: {eval_result['entropy_bits']} bits)")
        if not eval_result["is_strong"] and eval_result["recommendations"]:
            for rec in eval_result["recommendations"]:
                print(f"  Recommendation: {rec}")

        confirm_pass = getpass.getpass("\nConfirm master password: ")
        if master_pass != confirm_pass:
            print("Error: Passwords do not match.")
            return

        try:
            self.auth.create_vault(master_pass, confirm_pass)
            print("\nVault created successfully.")
        except VaultSecurityException as e:
            print(f"Error: {e}")

    def handle_unlock_vault(self) -> None:
        """FR2: Unlock vault with master password."""
        print("\nUNLOCK YOUR VAULT")
        print("-" * 30)
        if not self.manager.is_initialized:
            print("Error: No vault found. Please create a vault first using option [2].")
            return

        master_pass = getpass.getpass("Master password: ")
        try:
            self.auth.authenticate(master_pass)
            print("\nAuthentication successful.")
            print("Vault unlocked.")
        except AuthenticationError:
            print("\nAuthentication failed.")
            print("Vault remains locked.")
        except RateLimitExceededError as e:
            print(f"\n{e}")
        except Exception as e:
            print(f"\nAuthentication failed: {e}")
            print("Vault remains locked.")

    def handle_add_credential(self, service: str = None, username: str = None, password: str = None) -> None:
        """FR3: Add service credential."""
        if not self.manager.is_unlocked:
            print("Vault is locked.\nAuthentication required.")
            return

        self.auth.touch_session()

        if not service or not username or not password:
            print("\nADD A NEW CREDENTIAL")
            print("-" * 35)

        if not service:
            service = input("Website / App Name (e.g. github, google, netflix): ").strip()
        if not username:
            username = input("Username or Email: ").strip()
        if not password:
            password = getpass.getpass("Password (hidden while typing): ")

        valid_svc, svc_err = InputValidator.validate_service_name(service)
        if not valid_svc:
            print(f"Error: {svc_err}")
            return

        valid_user, user_err = InputValidator.validate_username(username)
        if not valid_user:
            print(f"Error: {user_err}")
            return

        if not password:
            print("Error: Password cannot be empty.")
            return

        try:
            self.manager.add(service=service, username=username, password=password)
            self.audit.log_event("CREDENTIAL_ADDED", {"service": service})
            print("\nCredential stored successfully.")
        except DuplicateServiceError:
            print(f"Error: Service '{service}' already exists.\nUse UPDATE instead.")
        except VaultSecurityException as e:
            print(f"Error: {e}")

    def handle_list_services(self) -> None:
        """FR4: List all stored service names."""
        if not self.manager.is_unlocked:
            print("Vault is locked.\nAuthentication required.")
            return

        self.auth.touch_session()
        services = self.manager.list_services()
        if not services:
            print("\nYour vault is empty. Use option [1] to add your first account.")
            return

        print("\nStored Services:")
        print("----------------")
        for idx, svc in enumerate(services, start=1):
            print(f"{idx}. {svc}")

    def handle_get_credential(self, service: str = None) -> None:
        """FR5: Retrieve credential with password masked."""
        if not self.manager.is_unlocked:
            print("Vault is locked.\nAuthentication required.")
            return

        self.auth.touch_session()

        if not service:
            services = self._display_accounts_summary()
            if not services:
                print("Vault is empty. No accounts saved yet.")
                return
            service = input("Enter Account Name (e.g. github) or Number: ").strip()

        resolved_service = self._resolve_service_name(service)

        try:
            cred = self.manager.get(resolved_service)
            self.audit.log_event("CREDENTIAL_RETRIEVED", {"service": cred["service"]})
            print(f"\nService: {cred['service']}")
            print(f"Username: {cred['username']}")
            print(f"Password: {cred['password']}")
            if cred.get("category") and cred["category"] != "General":
                print(f"Category: {cred['category']}")
            if cred.get("notes"):
                print(f"Notes: {cred['notes']}")
        except ServiceNotFoundError:
            print(f"Error: Credential not found for '{service}'.")
        except VaultSecurityException as e:
            print(f"Error: {e}")

    def handle_reveal_password(self, service: str = None) -> None:
        """FR5 Explicit: Reveal plaintext password after confirmation."""
        if not self.manager.is_unlocked:
            print("Vault is locked.\nAuthentication required.")
            return

        self.auth.touch_session()

        if not service:
            services = self._display_accounts_summary()
            if not services:
                print("Vault is empty. No accounts saved yet.")
                return
            service = input("Enter Account Name (e.g. github) or Number to reveal password: ").strip()

        resolved_service = self._resolve_service_name(service)

        try:
            self.manager.get(resolved_service)
        except ServiceNotFoundError:
            print(f"Error: Credential not found for '{service}'.")
            return

        confirm = input(f"Are you sure you want to reveal the password for '{resolved_service}'? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Reveal cancelled.")
            return

        try:
            pwd = self.manager.reveal(resolved_service)
            self.audit.log_event("CREDENTIAL_REVEALED", {"service": resolved_service})
            print(f"\nPassword for {resolved_service}: {pwd}")
        except ServiceNotFoundError:
            print(f"Error: Credential not found for '{service}'.")

    def handle_update_credential(self, service: str = None) -> None:
        """FR6: Update an existing credential."""
        if not self.manager.is_unlocked:
            print("Vault is locked.\nAuthentication required.")
            return

        self.auth.touch_session()

        if not service:
            services = self._display_accounts_summary()
            if not services:
                print("Vault is empty. No accounts saved yet.")
                return
            service = input("Enter Account Name (e.g. github) or Number to update: ").strip()

        resolved_service = self._resolve_service_name(service)

        try:
            current_view = self.manager.get(resolved_service)
        except ServiceNotFoundError:
            print(f"Error: Credential for '{service}' not found.")
            return

        print(f"\nUpdating '{current_view['service']}' (press Enter to keep current value):")
        new_username = input(f"Username [{current_view['username']}]: ").strip()
        new_password = getpass.getpass("New password (leave blank to keep current): ")
        new_category = input(f"Category [{current_view['category']}]: ").strip()
        new_notes = input(f"Notes [{current_view['notes']}]: ").strip()

        try:
            self.manager.update(
                service=resolved_service,
                username=new_username if new_username else None,
                password=new_password if new_password else None,
                category=new_category if new_category else None,
                notes=new_notes if new_notes else None,
            )
            self.audit.log_event("CREDENTIAL_UPDATED", {"service": resolved_service})
            print("\nCredential updated successfully.")
        except VaultSecurityException as e:
            print(f"Error: {e}")

    def handle_delete_credential(self, service: str = None) -> None:
        """FR7: Delete a service credential."""
        if not self.manager.is_unlocked:
            print("Vault is locked.\nAuthentication required.")
            return

        self.auth.touch_session()

        if not service:
            services = self._display_accounts_summary()
            if not services:
                print("Vault is empty. No accounts saved yet.")
                return
            service = input("Enter Account Name (e.g. github) or Number to delete: ").strip()

        resolved_service = self._resolve_service_name(service)

        try:
            self.manager.get(resolved_service)
        except ServiceNotFoundError:
            print(f"Error: Service '{service}' not found.")
            return

        confirm = input(f"Confirm deletion of '{resolved_service}'? [y/N]: ").strip().lower()
        if confirm == "y":
            try:
                deleted_name = self.manager.delete(resolved_service)
                self.audit.log_event("CREDENTIAL_DELETED", {"service": deleted_name})
                print("\nCredential deleted successfully.")
            except VaultSecurityException as e:
                print(f"Error: {e}")
        else:
            print("Deletion cancelled.")

    def handle_search(self, query: str = None) -> None:
        """FR8: Search services."""
        if not self.manager.is_unlocked:
            print("Vault is locked.\nAuthentication required.")
            return

        self.auth.touch_session()
        if not query:
            query = input("Enter search keyword (e.g. 'git', 'mail', 'work'): ").strip()

        results = self.manager.search(query)
        if not results:
            print("No matching services found.")
            return

        print(f"\nMatching services ({len(results)} found):")
        print("-----------------------------------")
        for res in results:
            cat_info = f" [{res['category']}]" if res.get("category") and res["category"] != "General" else ""
            print(f"- {res['service']}{cat_info} (User: {res['username']})")

    def handle_lock(self) -> None:
        """FR9: Explicitly lock the vault."""
        if not self.manager.is_unlocked:
            print("Vault is already locked.")
            return

        self.auth.lock_vault()
        print("\nVault locked.")

    def handle_exit(self) -> None:
        """FR10: Securely exit application."""
        if self.manager.is_unlocked:
            self.auth.lock_vault()
            print("Vault locked.")
        print("Goodbye.")
        self.running = False

    def handle_generate_password(self) -> None:
        """Generate a random high-entropy password."""
        print("\nSECURE PASSWORD GENERATOR")
        print("-" * 35)
        length_str = input("Desired password length [default 16]: ").strip()
        length = int(length_str) if length_str.isdigit() else 16
        password = PasswordGenerator.generate(length=length)
        eval_res = PasswordStrengthEvaluator.evaluate(password)
        print(f"\nGenerated Password: {password}")
        print(f"Strength Rating: {eval_res['label']} ({eval_res['score']}/100, Entropy: {eval_res['entropy_bits']} bits)")

    def handle_change_master_password(self) -> None:
        """Rotate key and change master password."""
        if not self.manager.is_unlocked:
            print("Vault is locked.\nAuthentication required.")
            return

        print("\nCHANGE MASTER PASSWORD")
        print("-" * 35)
        current_pass = getpass.getpass("Enter CURRENT master password: ")
        try:
            self.manager.storage.unlock_and_load(current_pass)
        except Exception:
            print("Error: Current master password is incorrect.")
            return

        new_pass = getpass.getpass("Enter NEW master password: ")
        if not new_pass:
            print("Error: New master password cannot be empty.")
            return

        confirm_pass = getpass.getpass("Confirm NEW master password: ")
        if new_pass != confirm_pass:
            print("Error: Passwords do not match.")
            return

        try:
            self.manager.change_master_password(new_pass)
            self.audit.log_event("MASTER_PASSWORD_CHANGED")
            print("\nMaster password updated and vault re-encrypted successfully.")
        except Exception as e:
            print(f"Error changing master password: {e}")

    def handle_audit_log(self) -> None:
        """Display recent security audit log entries."""
        entries = self.audit.get_recent_entries(limit=15)
        if not entries:
            print("\nNo security events recorded yet.")
            return

        print("\nRecent Security Audit Log (Passwords are never logged):")
        print("-" * 55)
        for entry in entries:
            ts = entry.get("timestamp", "")
            evt = entry.get("event", "")
            dtl = entry.get("details", {})
            dtl_str = f" | {dtl}" if dtl else ""
            print(f"[{ts}] {evt}{dtl_str}")

    def handle_backup(self) -> None:
        """Create an encrypted backup of the vault."""
        default_backup = self.vault_path.with_name(f"vault_backup_{self.vault_path.name}")
        print("\nBACKUP ENCRYPTED VAULT")
        print("-" * 35)
        backup_str = input(f"Destination path [{default_backup}]: ").strip()
        backup_path = Path(backup_str) if backup_str else default_backup

        try:
            self.manager.storage.create_backup(backup_path)
            self.audit.log_event("VAULT_BACKUP_CREATED", {"backup_path": str(backup_path)})
            print(f"\nVault backup created successfully at: {backup_path}")
        except Exception as e:
            print(f"Error creating backup: {e}")

    def execute_command_string(self, cmd_line: str) -> None:
        """
        Parse and execute command-line syntax e.g.:
        ADD github user123 secret
        GET github
        LIST
        SEARCH git
        DELETE github
        LOCK
        EXIT
        """
        try:
            tokens = shlex.split(cmd_line.strip())
        except ValueError as e:
            print(f"Command parsing error: {e}")
            return

        if not tokens:
            return

        verb = tokens[0].upper()

        if verb == "CREATE":
            self.handle_create_vault()
        elif verb == "UNLOCK":
            self.handle_unlock_vault()
        elif verb == "ADD":
            if len(tokens) >= 4:
                self.handle_add_credential(service=tokens[1], username=tokens[2], password=tokens[3])
            elif len(tokens) == 2:
                self.handle_add_credential(service=tokens[1])
            else:
                self.handle_add_credential()
        elif verb == "GET":
            svc = tokens[1] if len(tokens) > 1 else None
            self.handle_get_credential(svc)
        elif verb == "REVEAL":
            svc = tokens[1] if len(tokens) > 1 else None
            self.handle_reveal_password(svc)
        elif verb == "LIST":
            self.handle_list_services()
        elif verb == "UPDATE":
            svc = tokens[1] if len(tokens) > 1 else None
            self.handle_update_credential(svc)
        elif verb == "DELETE":
            svc = tokens[1] if len(tokens) > 1 else None
            self.handle_delete_credential(svc)
        elif verb == "SEARCH":
            query = tokens[1] if len(tokens) > 1 else ""
            self.handle_search(query)
        elif verb == "GENERATE":
            self.handle_generate_password()
        elif verb == "LOCK":
            self.handle_lock()
        elif verb in ("EXIT", "QUIT"):
            self.handle_exit()
        elif verb == "AUDIT":
            self.handle_audit_log()
        elif verb == "BACKUP":
            self.handle_backup()
        elif verb == "HELP":
            self.print_help()
        else:
            print(f"Unknown command: '{tokens[0]}'. Type HELP for available commands.")

    def print_help(self) -> None:
        """Print list of direct commands."""
        print("\nDirect Commands Available:")
        print("  ADD <website> <user> <pass>  - Add a login (e.g. ADD github vishal secret123)")
        print("  GET <website>                - View login info (e.g. GET github)")
        print("  REVEAL <website>             - View real plaintext password (e.g. REVEAL github)")
        print("  LIST                         - View all saved accounts")
        print("  SEARCH <word>                - Search accounts (e.g. SEARCH git)")
        print("  UPDATE <website>             - Edit an account")
        print("  DELETE <website>             - Delete an account")
        print("  GENERATE                     - Make a new strong password")
        print("  LOCK                         - Lock your vault")
        print("  EXIT                         - Exit program")

    def run_interactive(self) -> None:
        """Run the interactive CLI event loop."""
        self.print_banner()

        while self.running:
            try:
                # Check for session inactivity timeout
                if self.auth.check_session_timeout():
                    print("\n[Notice] Session timed out due to inactivity. Vault has been locked.")

                self.print_main_menu()
                choice = input("\nEnter your choice or command: ").strip()
                if not choice:
                    continue

                # Check if choice is a direct text command (e.g. "ADD github ...", "GET github", "LIST")
                first_word = choice.split()[0].upper()
                if first_word in {
                    "CREATE", "UNLOCK", "ADD", "GET", "REVEAL", "LIST",
                    "UPDATE", "DELETE", "SEARCH", "LOCK", "EXIT", "QUIT",
                    "GENERATE", "AUDIT", "BACKUP", "HELP"
                }:
                    self.execute_command_string(choice)
                    continue

                # Otherwise process as numerical menu choice
                if not self.manager.is_unlocked:
                    if choice == "1":
                        self.handle_unlock_vault()
                    elif choice == "2":
                        self.handle_create_vault()
                    elif choice == "3":
                        self.handle_generate_password()
                    elif choice in ("4", "q", "exit"):
                        self.handle_exit()
                    else:
                        print("Invalid choice. Please choose a number from 1 to 4.")
                else:
                    if choice == "1":
                        self.handle_add_credential()
                    elif choice == "2":
                        self.handle_get_credential()
                    elif choice == "3":
                        self.handle_list_services()
                    elif choice == "4":
                        self.handle_update_credential()
                    elif choice == "5":
                        self.handle_delete_credential()
                    elif choice == "6":
                        self.handle_search()
                    elif choice == "7":
                        self.handle_reveal_password()
                    elif choice == "8":
                        self.handle_generate_password()
                    elif choice == "9":
                        self.handle_change_master_password()
                    elif choice == "10":
                        self.handle_audit_log()
                    elif choice == "11":
                        self.handle_backup()
                    elif choice == "12":
                        self.handle_lock()
                    elif choice in ("13", "q", "exit"):
                        self.handle_exit()
                    else:
                        print("Invalid choice. Please choose a number from 1 to 13.")

            except KeyboardInterrupt:
                print("\nInterrupted.")
                self.handle_exit()
            except Exception as e:
                print(f"\nAn error occurred: {e}")
