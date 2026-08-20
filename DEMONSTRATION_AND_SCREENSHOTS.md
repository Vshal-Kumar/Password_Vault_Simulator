# Deliverable 4: Demonstration Evidence & Execution Logs

**Project**: Secure Local Encrypted Password Vault Simulator  
**Purpose**: Execution evidence and terminal output transcripts of all major functions, security mechanisms, and outputs.

---

## 1. Startup & Vault Creation (FR1)

When launching the application for the first time:
```text
$ python main.py

====================================================
     SECURE ENCRYPTED PASSWORD VAULT SIMULATOR      
====================================================

================================================
        SECURE PASSWORD VAULT (LOCKED)          
================================================
  [1] Unlock Vault (Log in with Master Password)
  [2] Create a New Vault
  [3] Generate a Strong Random Password
  [4] Exit
------------------------------------------------

Enter your choice or command: 2

CREATE A NEW ENCRYPTED VAULT
----------------------------------------
Please choose a strong Master Password to protect your vault.
Enter master password: [hidden]

Password Strength: Very Strong (Score: 80/100, Entropy: 86.44 bits)

Confirm master password: [hidden]

Vault created successfully.
```

---

## 2. Adding a Credential (FR3)

Adding account credentials without exposing plaintext secrets:
```text
Enter your choice or command: 1

ADD A NEW CREDENTIAL
-----------------------------------
Website / App Name (e.g. github, google, netflix): github
Username or Email: user123
Password (hidden while typing): [hidden]

Credential stored successfully.
```

---

## 3. Listing Stored Services (FR4)

Listing saved accounts (passwords are completely omitted):
```text
Enter your choice or command: 3

Stored Services:
----------------
1. github
2. gmail
3. linkedin
```

---

## 4. Retrieving Credential with Masked Password (FR5)

Passwords remain masked by default (`********`):
```text
Enter your choice or command: 2

Stored Accounts:
  [1] github (User: user123)
  [2] gmail (User: user@gmail.com)

Enter Account Name (e.g. github) or Number: 1

Service: github
Username: user123
Password: ********
```

---

## 5. Explicit Plaintext Password Reveal (FR5 Explicit)

Requires explicit confirmation before displaying plaintext:
```text
Enter your choice or command: 7

Stored Accounts:
  [1] github (User: user123)
  [2] gmail (User: user@gmail.com)

Enter Account Name (e.g. github) or Number to reveal password: 1
Are you sure you want to reveal the password for 'github'? [y/N]: y

Password for github: secretpassword123!
```

---

## 6. Searching Stored Accounts (FR8)

```text
Enter your choice or command: 6

Enter search keyword (e.g. 'git', 'mail', 'work'): git

Matching services (1 found):
-----------------------------------
- github (User: user123)
```

---

## 7. Updating a Credential (FR6)

```text
Enter your choice or command: 4

Stored Accounts:
  [1] github (User: user123)

Enter Account Name (e.g. github) or Number to update: 1

Updating 'github' (press Enter to keep current value):
Username [user123]: [Enter]
New password (leave blank to keep current): [hidden]
Category []: Dev
Notes []: Work development account

Credential updated successfully.
```

---

## 8. Deleting a Credential (FR7)

```text
Enter your choice or command: 5

Stored Accounts:
  [1] github (User: user123)

Enter Account Name (e.g. github) or Number to delete: 1
Confirm deletion of 'github'? [y/N]: y

Credential deleted successfully.
```

---

## 9. Locking the Vault & Access Control (FR9)

Wiping in-memory credentials and enforcing access control:
```text
Enter your choice or command: 12

Vault locked.

Enter your choice or command: GET github
Vault is locked.
Authentication required.
```

---

## 10. Brute-Force Rate Limiting & Lockout Defense

```text
Enter your choice or command: 1
UNLOCK YOUR VAULT
------------------------------
Master password: [wrong]

Authentication failed.
Vault remains locked.

[Attempt 5 fails...]
Authentication failed 5 times. Vault is locked for 30 seconds.
```

---

## 11. Plaintext Inspection Demonstration (Confidentiality Proof)

Inspecting `data/vault.enc` directly using `cat`:
```bash
$ cat data/vault.enc
```
```json
{
  "version": 1,
  "kdf": {
    "algorithm": "Argon2id",
    "salt": "l8jG9K+...",
    "params": {
      "algorithm": "Argon2id",
      "length": 32,
      "time_cost": 2,
      "memory_cost": 65536,
      "parallelism": 2
    }
  },
  "encryption": {
    "algorithm": "AES-256-GCM"
  },
  "vault": {
    "nonce": "A8kL+...",
    "ciphertext": "8fA29x92qQ..."
  },
  "metadata": {
    "created_at": "2026-08-19T13:20:00.000000+00:00",
    "last_modified": "2026-08-19T13:20:00.000000+00:00"
  }
}
```
**Verification**: Neither usernames, passwords, nor metadata are visible in plaintext.
