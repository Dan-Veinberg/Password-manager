Absolutely 👍 — here’s a clear, polished **README.md** you can include with your project so anyone can easily understand, install, and use your console-based password manager.

---

## 📘 README.md

# 🔐 Console Password Manager (SQLite + AES-256)

A simple, secure **command-line password manager** built with **Node.js** and **SQLite**.
All stored passwords are encrypted with **AES-256-GCM** using a key derived from your **master password** via **scrypt**. Perfect if you do not want to use any of the current commercial solutions because care about privacy. 

---

## 🚀 Features

✅ Local-only, no internet connection needed
✅ AES-256-GCM encryption for all passwords
✅ Master password–based vault encryption
✅ SQLite database for durability
✅ Full CRUD interface in the console
✅ Search, archive, export, and password update support
✅ Safe retry logic (won’t quit after one bad attempt)
✅ No double-typing bug for hidden input

---

## 📦 Requirements

* [Node.js](https://nodejs.org) (v18 or newer recommended)
* [SQLiteStudio](https://sqlitestudio.pl/) *(optional, for inspecting the DB)*

---

## 🧰 Setup

1. Clone or copy this project:

   ```bash
   git clone https://github.com/yourusername/pwman.git
   cd pwman
   ```

2. Initialize dependencies:

   ```bash
   npm install
   ```

3. Verify your **package.json** includes this line:

   ```json
   {
     "type": "module"
   }
   ```

4. Run the app:

   ```bash
   node app.mjs
   ```

---

## 🔑 First Run

On the first launch, the app will create a new encrypted database file:

```
vault.db
vault.db-shm
vault.db-wal
```

You’ll be prompted to create a **master password**:

```
Create master password:
Confirm master password:
Master password initialized.
```

That password encrypts your vault. If you forget it, there’s **no recovery** — the data is cryptographically locked.

---

## 🧭 Commands

| Command          | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `add`            | Add a new entry (title, username, password, etc.)            |
| `list`           | List all entries                                             |
| `list all`       | Include archived entries                                     |
| `search <text>`  | Search by title, username, tags                              |
| `view <id>`      | Show details (no password)                                   |
| `show <id>`      | Reveal decrypted password                                    |
| `update <id>`    | Edit entry fields                                            |
| `passwd <id>`    | Change stored password                                       |
| `archive <id>`   | Archive an entry                                             |
| `unarchive <id>` | Unarchive it                                                 |
| `del <id>`       | Permanently delete an entry                                  |
| `export`         | Export all data (encrypted fields included) to `export.json` |
| `quit`           | Exit the app                                                 |

Example:

```
> add
title: GitHub
url: https://github.com
username: dan@example.com
tags (comma-separated): work,dev
notes (non-sensitive): main account
password: ********
Added entry #1
```

---

## 🔒 File Security

* Your vault (`vault.db`) is encrypted, but titles/usernames are stored in plaintext for searching.
* Protect your vault folder using OS-level permissions:

### macOS / Linux

```bash
chmod 600 vault.db*
```

### Windows PowerShell

```powershell
icacls vault.db* /inheritance:r /grant:r "%USERNAME%:F"
```

For stronger security, keep your vault inside an encrypted folder (e.g. FileVault, BitLocker, VeraCrypt).

---

## 🧹 Resetting the Vault

If you want to start over or forgot your master password:

1. Close the app.
2. Delete these files:

   ```
   vault.db
   vault.db-wal
   vault.db-shm
   ```
3. Run the app again:

   ```bash
   node app.mjs
   ```
4. You’ll be prompted to create a new master password.

---

## ⚠️ Important Notes

* There’s **no password recovery** — if you forget your master password, your data is lost forever.
* Back up `vault.db` periodically to an encrypted drive.
* `.wal` and `.shm` files are temporary; SQLite recreates them automatically.

---

## 🧑‍💻 Optional Improvements

You can easily extend this app:

* Add **favorites** or **tags filtering**
* Implement **password generator**
* Auto-lock after X minutes idle
* Add **HMAC integrity check** to detect file tampering
* GUI version using Electron or Tauri

---

## 📁 Project Structure

```
📂 pwman/
 ├── app.mjs        # Main program
 ├── package.json   # Dependencies & ESM config
 ├── README.md      # This file
 └── vault.db*      # Database (auto-created)
```

---

## 📜 License

MIT License – free for personal or educational use.

---

Would you like me to include a short “example session” section (with screenshots of how adding, listing, and showing passwords looks in the console)? It makes the README feel more polished for GitHub.
