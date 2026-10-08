# Penkeeper

A self-hosted, single-binary web application for managing penetration test assessments. Track hosts, ports, credentials, notes, and tool output — all in one place — with a companion CLI (`pk`) that pipes terminal output directly into the interface.

---

## Features

- **Assessments** — Create and manage multiple engagements. Each assessment has its own hosts, data, and activity log.
- **Hosts** — Add hosts by IP address, CIDR range or hostname. Track OS, device type, and a custom label per host.
- **Ports** — Log open ports with protocol, service name, and banner info. Import directly from Nmap XML.
- **Credentials** — Store username/password/hash pairs per host. Passwords and hashes are encrypted at rest and masked in the UI.
- **Commands** — Log commands run against a host with optional notes. A global Commands library lets you save reusable command references across all assessments.
- **Notes** — Rich-text per-host notes with a file manager, formatting toolbar (bold, italic, highlight, code blocks, lists), and templates (Recon, Exploitation, Post-Exploitation, Loot).
- **Services (Tool Output)** — View terminal output piped in via the `pk` CLI, organized by tool and timestamp.
- **`pk` CLI** — Pipe any tool's output to a host from your terminal. Supports stdin piping and interactive PTY mode (`--run`) for tools like `smbclient` that need a real TTY.
- **Search** — Full-text search across assessments, hosts, credentials, notes, and commands.
- **Authentication** — JWT-based login with optional TOTP two-factor authentication (QR code setup in Settings).
- **Dark / Light mode** — One Dark Pro-inspired dark theme with a light mode toggle.
- **Single binary** — The frontend is embedded at build time. One file to deploy, no web server required.

---

## Screenshots

> Add screenshots here after first run. Suggested captures:
> - Dashboard
> - Assessment overview (host list + sidebar)
> - Host detail (Ports tab, Commands tab)
> - Commands library (global tab)
> - Notes editor

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| [Go](https://go.dev/dl/) | 1.24+ | Required to build (see `go.mod`) |
| [PostgreSQL](https://www.postgresql.org/) | 14+ | Database backend |

Runs on **Linux** and **macOS**. On macOS, install [Homebrew](https://brew.sh) first — `setup.sh` uses it to install and manage PostgreSQL (and Go, if missing). No other runtime dependencies: the compiled binary embeds all HTML, CSS, and JavaScript.

---

## Quick Setup

The included `setup.sh` script handles everything — it detects your OS and runs
the right path for **Linux** (Debian/Kali/Ubuntu, systemd) or **macOS**
(Homebrew): PostgreSQL setup, `.env` generation, and building both binaries.

```bash
# Clone the repository
git clone https://github.com/jortles/penkeeper.git
cd penkeeper
```

**Linux (Debian / Kali / Ubuntu)** — run with `sudo` (needed for systemd, the
`postgres` user, and installing `pk` to `/usr/local/bin`):

```bash
sudo ./setup.sh
```

**macOS (Homebrew)** — run **without** `sudo` (Homebrew refuses to run as root,
and its PostgreSQL runs as your user). Requires [Homebrew](https://brew.sh); the
script installs PostgreSQL (and Go, if missing) for you:

```bash
./setup.sh
```

The script performs these steps automatically:

| Step | What it does |
|---|---|
| 1 | Verifies Go is installed (installs it via Homebrew on macOS if missing) |
| 2 | Installs (macOS) and starts the PostgreSQL service |
| 3 | Creates the `penkeeper` database role with a random password |
| 4 | Creates the `penkeeper` database |
| 5 | Enables the `uuid-ossp` extension |
| 6 | Writes `.env` (mode `600`) from `.env.example` with a random `JWT_SECRET`, `ENCRYPTION_KEY` and database password |
| 7 | Builds the `./server` binary (embedded frontend) |
| 8 | Builds and installs `pk` (to `/usr/local/bin` on Linux, or your Homebrew `bin` on macOS) |

Re-running the script keeps an existing `.env`. It never generates new secrets
for a database that already holds data: if `penkeeper` has users but `.env`
is missing (for example after re-cloning or moving the checkout), it stops and
asks you to copy the old `.env` back, because new keys would make every stored
credential and 2FA secret unreadable. If it has to create the `penkeeper` role, it
writes the new password into `DATABASE_URL` only when that points at the local
`penkeeper` database; any other `DATABASE_URL` is kept and the local one is
printed instead.

---

## Starting the Server

```bash
./server        # or: make run
```

The server automatically loads a `.env` file from the working directory, so no
`source .env` step is needed. Real environment variables always override values
in the file. The server listens on port `1338` by default — open
`http://localhost:1338` in your browser.

On first launch, the server prompts in the terminal to create an admin account.
All subsequent logins use those credentials.

### Running as a Background Service

```bash
# Start in the background, log to a file only you can read
(umask 077 && nohup ./server > penkeeper.log 2>&1 &)

# Or with systemd (see below)
```

<details>
<summary>systemd unit file</summary>

Create `/etc/systemd/system/penkeeper.service`:

```ini
[Unit]
Description=Penkeeper
After=network.target postgresql.service

[Service]
Type=simple
WorkingDirectory=/opt/penkeeper
EnvironmentFile=/opt/penkeeper/.env
ExecStart=/opt/penkeeper/server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now penkeeper
```

</details>

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *(written by setup.sh with a random password)* | PostgreSQL connection string, e.g. `postgres://penkeeper:<password>@localhost:5432/penkeeper?sslmode=disable` |
| `JWT_SECRET` | *(generated by setup.sh)* | Secret for signing JWT tokens. Required: at least 32 bytes (`openssl rand -hex 32`). The server refuses to start with the old `.env.example` placeholder, unexpanded shell syntax such as `$(...)`, or a shorter value. |
| `PORT` | `1338` | HTTP listen port |
| `ENCRYPTION_KEY` | *(derived from `JWT_SECRET`)* | Secret used to encrypt credentials & TOTP secrets at rest. Set explicitly — see [Encryption key](#encryption-key) below. |
| `ALLOWED_ORIGINS` | *(unset)* | Comma-separated CORS origins for cross-origin deployments. These origins also pass the cross-site request check. |
| `TRUSTED_PROXIES` | *(unset)* | Comma-separated proxy IPs/CIDRs to trust for `X-Forwarded-For`. Leave unset when running directly; set it to your reverse proxy only when behind one. If unset, no proxy headers are trusted (so the rate limiter keys on the real connection IP). From these proxies, the origin in `X-Forwarded-Proto` and `X-Forwarded-Host` also passes the cross-site request check. |
| `SMTP_HOST` | *(unset)* | SMTP server for password reset emails. If unset, reset URLs are logged to stdout. |
| `SMTP_PORT` | `587` | `587` = STARTTLS, `465` = implicit TLS |
| `SMTP_USER` | *(unset)* | SMTP username |
| `SMTP_PASS` | *(unset)* | SMTP password |
| `SMTP_FROM` | *(= SMTP_USER)* | From address for reset emails |
| `APP_URL` | `http://localhost:PORT` | Public URL used in password reset links. Its origin is also accepted by the cross-site request check, so set it when users reach the app through a reverse proxy. |
| `PK_ALLOW_INSECURE_SECRETS` | *(unset)* | `1` starts the server despite insecure secrets, with a warning (local development only). `ENCRYPTION_KEY` allows only a weak `ENCRYPTION_KEY`, for data already encrypted under one (see below). |

A variable exported in your shell overrides `.env`.

`.env` takes one `KEY=value` per line, with comments on their own lines. It is
not run through a shell, so paste generated values: `JWT_SECRET=$(openssl rand
-hex 32)` would set the literal text, and the server refuses it.

### Encryption key

Credentials and TOTP secrets are encrypted at rest with AES-256-GCM. The key is
derived (`SHA-256`) from the `ENCRYPTION_KEY` value, so the value can be any
string — but it should be **high-entropy and random**, not a memorable phrase.

Generate one with:

```bash
openssl rand -hex 32
```

**On a fresh install (empty database), just set it and go.** Use a random value
*different* from `JWT_SECRET` — two independent secrets is the ideal end state:

```bash
JWT_SECRET=<openssl rand -hex 32>
ENCRYPTION_KEY=<a different openssl rand -hex 32>
```

Then **never change `ENCRYPTION_KEY` again.** It only protects data once you
start saving credentials; before that it's free to set, but afterward changing
it makes all existing encrypted data undecryptable. The server then logs a
warning at startup, the UI shows those passwords and hashes as "cannot be
decrypted" (editing such a credential keeps the stored value unless you type a
new one), and exports are refused, until the original key is restored.

**Already running with data?** If `ENCRYPTION_KEY` was unset, your existing
credentials are encrypted with a key derived from `JWT_SECRET`. To adopt
`ENCRYPTION_KEY` without a migration, set it to the **exact current value of
`JWT_SECRET`** — this yields the same key, so existing data still decrypts, and
you can afterward rotate `JWT_SECRET` (to invalidate sessions) without touching
your encrypted data. Setting a *brand-new* random key on a database that already
has credentials requires a re-encryption migration instead.

If `ENCRYPTION_KEY` is left unset, the server derives it from `JWT_SECRET` and
logs a warning at startup.

**Server refuses to start because `JWT_SECRET` is insecure?** Rotate it without
losing encrypted data: add `ENCRYPTION_KEY=<the current JWT_SECRET value>` (the
same key, as above), add `PK_ALLOW_INSECURE_SECRETS=ENCRYPTION_KEY` because that
value is weak, then set `JWT_SECRET` to a new `openssl rand -hex 32` value.
Everyone has to log in again. Data saved under the weak key stays only as
protected as it was.

---

## Manual Build

If you want to build without running `setup.sh`, use the `Makefile`:

```bash
make            # build ./server (embedded frontend)
make cli        # build ./pk
make install    # install pk to /usr/local/bin (needs sudo)
make run        # build and run the server
make clean      # remove built binaries
```

Or invoke `go build` directly:

```bash
# Server binary (with embedded frontend)
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o ./server ./cmd/server

# pk CLI
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /usr/local/bin/pk ./cmd/pk
```

---

## The `pk` CLI

`pk` is the terminal companion for Penkeeper. It lets you pipe tool output from your terminal directly into a host's **Services** tab without leaving the command line.

### Authentication

Run `pk login` to authenticate. It prompts for your server URL, email, and password (plus a TOTP code if 2FA is enabled) and saves the session token to `~/.config/penkeeper/config.json`. The token expires after 24 hours, so log in again at the start of each working day; output sent with an expired token is kept locally (see [When the upload fails](#when-the-upload-fails)).

```
$ pk login
API URL [http://localhost:1338]:
Email: user@example.com
Password:
[+] Logged in. Token saved to /home/user/.config/penkeeper/config.json
```

### Piping Tool Output

```bash
# Pipe any tool's stdout to a host
nmap -sV 10.10.10.5 | pk --target 10.10.10.5

# Specify the tool name and original command string
whatweb http://10.10.10.5 | pk --target 10.10.10.5 --tool whatweb --command "whatweb http://10.10.10.5"

# Pipe nikto output
nikto -h 10.10.10.5 | pk --target 10.10.10.5 --tool nikto
```

The output appears immediately in the **Services** tab of the matching host, labelled with the tool name and timestamp.

`--target` must be a host's identifier exactly as entered (letter case does not matter, but hosts written in the same case as `--target` come first); part of an identifier never matches, so `--target 10.10.10.5` does not pick `10.10.10.50`. When the identifier is a host in more than one of your assessments (the same private address for two clients, say), nothing is saved and `pk` lists them; choose one with `--assessment`, giving its name or its id:

```bash
nmap -sV 192.168.1.10 | pk --target 192.168.1.10 --assessment "ClientA-2026-01"
```

### When the upload fails

If the server does not save the output — expired session, no matching host, several matching hosts, server or network error, a server that does not answer within a minute — `pk` keeps it in a private file under `$XDG_STATE_HOME/pk/unsent` (`~/.local/state/pk/unsent` by default), prints its path and the command that sends it again, and exits with a non-zero status:

```
[!] Not saved on the server: session expired — run `pk login` to authenticate again
[*] Output kept in /home/user/.local/state/pk/unsent/20261008-093005-10.10.10.5-nmap-3508252463.txt
[*] To send it again: pk --target 10.10.10.5 --tool nmap < /home/user/.local/state/pk/unsent/20261008-093005-10.10.10.5-nmap-3508252463.txt
```

Delete the file once it has been sent.

### Running Commands Directly (`--run`)

For interactive tools that need a real TTY (password prompts, pagers, etc.), use `--run`. The command runs inside a PTY so interactive prompts work normally; both stdout and stderr are shown on your terminal in real-time, and the captured output is sent to the host. When `pk` itself is not run from a terminal (a script, `< /dev/null`), the command gets no PTY; its stdout and stderr are then shown on `pk`'s stdout and stderr and both captured. `pk` exits with the command's own exit status, so `pk --target … --run "…" && next-step` only runs `next-step` when the command succeeded (and its output was saved).

```bash
# Interactive smbclient session — prompts appear normally
pk --target 10.10.10.5 --run "smbclient //10.10.10.5/share -U admin"

# enum4linux — output captured and saved
pk --target 10.10.10.5 --run "enum4linux -a 10.10.10.5"

# curl with verbose output
pk --target 10.10.10.5 --run "curl -sv http://10.10.10.5/admin"
```

### All Flags

| Flag | Description |
|---|---|
| `--target <ip/host>` | Host identifier to attach output to *(required)*; matched exactly, ignoring case |
| `--assessment <name/id>` | Assessment the host is in; needed when the identifier is a host in several assessments |
| `--tool <name>` | Tool name tag shown in the Services tab. Defaults to the first word of `--command` or `--run`. |
| `--command <cmd>` | Command string saved for record-keeping (pipe mode) |
| `--run <cmd>` | Run this shell command in a PTY, capture its output, and exit with its status |

```bash
pk --help   # print usage
```

---

## Usage Guide

### 1. Create an Assessment

From the dashboard, click **New Assessment** and give it a name (e.g., the client or engagement name). Each assessment is independent with its own hosts and data.

### 2. Add Hosts

Inside an assessment, click **Add Host**. Enter the IP address or hostname. You can optionally set a label, OS, and device type — or edit them inline later by clicking directly on those fields in the host view.

### 3. Host Tabs

Each host has five tabs (drag to reorder):

| Tab | Contents |
|---|---|
| **Ports** | Open ports with protocol, service, and banner. Import from Nmap XML via the "Import Nmap" button. |
| **Services** | Tool output piped in via `pk`. Click a row to expand the full output. |
| **Credentials** | Username / password / hash pairs. Passwords are masked; click the eye icon to reveal. |
| **Commands** | Commands logged against this host, with optional notes. Click a row with notes to expand them. |
| **Notes** | Rich-text note files. Create multiple files per host, apply templates, and format with the toolbar. |

### 4. Logging Commands on a Host

The **Commands** tab on each host is for recording commands you ran during the engagement:

1. Open a host → click **Commands** tab → **+ Add Command**
2. Enter a **Name** (e.g., `Initial nmap`), the **Command** text, and optional **Notes** (findings, context, output summary)
3. Click **Save**

Commands with notes show a hover highlight — click the row to expand the notes inline.

### 5. Global Commands Library

The **Commands** link in the top navbar is a shared library of reusable command templates (reverse shells, enumeration one-liners, etc.), separate from per-host logged commands.

- Filter by **Category** and **OS**
- Live search across name, category, command text, and host
- The **Host** column shows which host a command came from (if it was added via the host Commands tab and appears in the global view)
- Click a row with notes to expand them

### 6. Nmap Import

In the **Ports** tab, click **Import Nmap** and select an XML file generated with `nmap -sV` (or `-sC -sV`). Open ports are imported with their service, version, and per-port NSE script output. Host-level script output (nmap's "Host script results", e.g. `smb-os-discovery` or `smb-vuln-ms17-010`) is not imported — paste it into a note.

A host's import only takes that host's entry from the file, so another machine's ports are never merged into it:

- A host named by IP address takes the entry with that address. A host named by hostname takes the entry with that hostname (case-insensitive). In a `-Pn` scan, an address with that name but no open port (e.g. one a stale PTR record still names) is ignored; the exception is the address you scanned the name as, which another machine that only has the name in its PTR record cannot replace. If several addresses nmap found up share the name (an HA pair, `--resolve-all`, or that exception), the import stops and asks you to set the host's identifier to one of them.
- If the file doesn't list the identifier, a host named by IP address gets nothing; any other host takes the one host of a single-target scan.
- If nmap lists the host as down, nothing is imported.

To import a scan of several hosts, click **Import Nmap** on the assessment overview instead. It adds a host for each address nmap found up (for `-Pn`, only those with open ports) and updates existing hosts whose identifier is that address, or a hostname only one scanned address has. In a `-Pn` scan where none of the addresses you scanned a name as has an open port, another machine that only has that name in its PTR record gets a host of its own instead of updating the host with that name.

Re-importing (e.g. `-sC -sV`, then `-p-`, then `-sV`) adds to what is stored and never makes it worse:

- Blank fields never erase stored values, and ports that are closed or filtered in the new scan are left alone.
- Weaker data never replaces better data: a port-number guess (a scan without `-sV`), `tcpwrapped`, or `unknown` never replaces a probed service name, and a result that names no product, or the stored product without an exact version, never replaces the stored version (`MySQL unauthorized` or `Samba smbd 3.X - 4.X` leaves `MySQL 8.0.36` or `Samba smbd 4.6.2` in place). If a probe finds a different service and no version, the old version is cleared.
- NSE output is merged per script: a new result replaces that script's old one, an `ERROR:` result never does, and results of scripts the new scan didn't run are kept.

Service and Info values you type in **Add Port** or **Edit Port** are shown in *italics*, and imports never replace them (they still fill a field you cleared, and NSE output still merges). To let scans update a value again, clear the field in **Edit Port**, or send `PUT /api/v1/hosts/<host id>/ports/<port id>` with `{"service_edited": false}` or `{"info_edited": false}`.

### 7. Credentials

Credentials are encrypted at rest using AES-256-GCM. The UI masks passwords and hashes by default. Use the copy buttons to put them on the clipboard without revealing them on screen.

**Exports** contain credential passwords and hashes in **plaintext** (so a bundle can be imported into an installation with a different encryption key). Import checks every row with the rules the app applies when you add it. Some values that break those rules are repaired and listed: an empty name becomes "Untitled assessment" (a name over 200 characters is shortened), a port with an invalid number or protocol is skipped, and NSE script output that is not a JSON array is dropped. If a host identifier is invalid, nothing is imported and the problems are listed. An export is refused if any stored credential cannot be decrypted (see [Encryption key](#encryption-key)), if a host identifier would be rejected on import (edit those hosts, then export again), or if the file would be larger than the 50 MB import limit, so every export can be restored. To protect them, enable "Encrypt export" in Settings → Data Transfer and choose a passphrase — the `.pne` file is then encrypted with AES-256-GCM using a key derived from your passphrase (scrypt). You must supply the same passphrase to import it. An unencrypted `.json` export is plaintext; store it accordingly.

### 8. Search

Click **Search** in the navbar to search across all assessments simultaneously. Results are grouped by type (hosts, credentials, notes, commands).

### 9. Two-Factor Authentication

Go to **Settings** (user menu → Settings) → **Two-Factor Authentication** → **Enable 2FA**. Scan the QR code with an authenticator app. After enabling, every login requires a 6-digit TOTP code. The `pk login` CLI command handles TOTP automatically. Disabling 2FA requires entering a current code, so a hijacked session cannot silently remove the second factor. While 2FA is enabled a new secret cannot be generated: disable 2FA first, then enable it again. Each code works only once, whether used to sign in, enable or disable.

Enabling or disabling 2FA signs out every other session of the account, including `pk` CLI tokens (run `pk login` again); the browser that made the change stays signed in. **Logout** ends the session on the server too, so a copy of its token stops working.

---

## Project Structure

```
penkeeper/
├── cmd/
│   ├── server/         # Main web server entry point
│   └── pk/             # CLI pipe tool
├── frontend/
│   ├── index.html      # SPA shell
│   ├── app.js          # All frontend logic (vanilla JS)
│   └── style.css       # Styles
├── internal/
│   ├── api/            # Gin route handlers
│   ├── crypto/         # AES-GCM encryption helpers
│   ├── email/          # SMTP password reset
│   ├── middleware/     # Auth, CSRF, body limits, security headers, logging
│   ├── model/          # GORM models
│   └── storage/        # Database connection + auto-migration
├── embed.go            # Embeds frontend/ into the server binary
├── .env.example        # Environment variable template
├── Makefile            # build / run / install helpers
└── setup.sh            # One-shot setup script
```

---

## Security Notes

- **Change `JWT_SECRET`** before exposing the server beyond localhost. `setup.sh` generates a random value automatically.
- **Set `ENCRYPTION_KEY`** explicitly instead of deriving it from `JWT_SECRET` — see [Encryption key](#encryption-key). On a fresh install use a random value different from `JWT_SECRET`; once credentials are saved, never change it.
- The application is intended for **local or VPN-restricted use** during an engagement. If you expose it to the internet, put it behind a reverse proxy (nginx/Caddy) with TLS. Behind a proxy, set `APP_URL` to the public URL users open; otherwise, unless the proxy is in `TRUSTED_PROXIES` and sends `X-Forwarded-Proto` and `X-Forwarded-Host`, browsers that send no `Sec-Fetch-Site` header (plain HTTP on a non-localhost address, older Safari) may have state-changing requests rejected as cross-site.
- **Give the app its own hostname.** Browsers send cookies to every port of a host, so the session cookie also reaches any other web service on the same hostname (for example a target app you port-forward to `localhost:8080` while using Penkeeper on `localhost:1338`), and a page there can plant cookies for this app. Serve Penkeeper on a dedicated hostname that no other service shares (e.g. a `penkeeper.internal` entry in DNS or `/etc/hosts`; on Linux a spare loopback address such as `127.0.0.2` also works).
- State-changing API requests from a browser must come from the app's own origin, `APP_URL`, `ALLOWED_ORIGINS` or the forwarded origin from a trusted proxy; others get `403`. The `pk` CLI (Bearer token) is unaffected. Scripts that authenticate with the session cookie must send a matching `Origin` header, or use a Bearer token instead.
- Request bodies are capped (1 MB by default; 20 MB for tool output, notes and the scratch pad; 50 MB for imports; 10 MB for Nmap files) and larger ones get `413`. At most two imports run at once. Slow or idle connections are closed by server timeouts.
- API responses are sent with `Cache-Control: no-store`, so decrypted credentials and exports are not kept in the browser's disk cache.
- Credentials stored in the database are encrypted at rest, but the encryption key is derived from environment variables — protect your `.env` file (`setup.sh` writes it with mode `600`).
- Password resets without SMTP configured print the reset link to server stdout. This is intentional for local use. Reset links carry the token after `#`, which browsers never send to the server, so opening a link does not put the token in access logs. Each link works once.

---

## License

MIT
