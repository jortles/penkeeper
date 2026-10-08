#!/usr/bin/env bash
#
# setup.sh — one-time setup for penkeeper.
#
# Supported platforms:
#   - Linux (Debian / Kali / Ubuntu): systemd-managed PostgreSQL.
#       Run WITH sudo:   sudo ./setup.sh
#   - macOS (Homebrew):  brew-managed PostgreSQL.
#       Run WITHOUT sudo:     ./setup.sh
#     (Homebrew refuses to run as root, and its PostgreSQL runs as your user.)
#
# What it does on both platforms:
#   1. Checks/installs prerequisites (Go, and on macOS, PostgreSQL)
#   2. Starts the PostgreSQL service
#   3. Creates the "penkeeper" role (random password) and "penkeeper" database
#   4. Enables the uuid-ossp extension
#   5. Generates .env (mode 600) with a random JWT_SECRET, ENCRYPTION_KEY and
#      database password. It never generates new secrets for a database that
#      already holds data: restore that install's .env instead.
#   6. Builds ./server and installs the pk CLI
#
# After running, start the server with:  ./server   (it auto-loads .env)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
DB_NAME="penkeeper"
DB_USER="penkeeper"
DB_PASS=""   # set when this run creates the role or resets its password
OS="$(uname -s)"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

require_cmd() { command -v "$1" >/dev/null 2>&1; }

# Run SQL as the PostgreSQL superuser: "postgres" on Linux, your own user with
# Homebrew. The SQL goes in on stdin, so passwords never appear in `ps`.
psql_admin() {
  if [ "${OS}" = "Linux" ]; then
    su - postgres -c "psql -X -q -tA -v ON_ERROR_STOP=1 -d $1" <<<"$2"
  else
    psql -X -q -tA -v ON_ERROR_STOP=1 -d "$1" <<<"$2"
  fi
}

database_url() {
  printf 'postgres://%s:%s@localhost:5432/%s?sslmode=disable' "${DB_USER}" "${DB_PASS}" "${DB_NAME}"
}

# managed_url URL: whether URL is the local role and database this script
# manages (so a new role password belongs in it).
managed_url() {
  local re="^postgres(ql)?://${DB_USER}(:[^@]*)?@(localhost|127\.0\.0\.1|\[::1\])(:5432)?/${DB_NAME}([?].*)?$"
  [[ "$1" =~ ${re} ]]
}

# write_env_file CONTENT: replace .env atomically, readable only by its owner.
write_env_file() {
  local tmp
  tmp="$(mktemp "${SCRIPT_DIR}/.env.XXXXXX")"
  printf '%s\n' "$1" > "${tmp}"
  chmod 600 "${tmp}"
  own_file "${tmp}"
  mv -f "${tmp}" "${ENV_FILE}"
}

# env_value KEY: print the value of the first KEY line in .env, parsed like
# the server does (optional leading spaces and "export", spaces around "=",
# one pair of matching quotes stripped). Fails when there is no KEY line.
env_value() {
  local line val
  line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=" "${ENV_FILE}" | head -n 1)" || true
  [ -n "${line}" ] || return 1
  val="$(sed -E -e 's/^[^=]*=[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${line}")"
  case "${val}" in
    \"*\" | \'*\') val="${val:1:${#val}-2}" ;;
  esac
  printf '%s' "${val}"
}

# Refuse an existing .env that still has an empty or placeholder JWT_SECRET
# (left by an older, interrupted run) before anything is changed. No
# JWT_SECRET line is fine: it may come from elsewhere, e.g. a systemd unit.
check_env_file() {
  [ -f "${ENV_FILE}" ] || return 0
  local jwt
  jwt="$(env_value JWT_SECRET)" || return 0
  if [ -z "${jwt}" ] || [ "${jwt}" = "change-me-to-a-random-secret" ]; then
    echo "Error: ${ENV_FILE} has no usable JWT_SECRET (empty or the .env.example placeholder)."
    echo "  If no data has been saved yet, delete it and re-run this script."
    echo "  Otherwise start ./server: it explains how to change JWT_SECRET without"
    echo "  losing encrypted data."
    exit 1
  fi
}

# When running as root on Linux (via sudo), give files back to the invoking
# user. No-op on macOS, where the script runs as the normal user.
own_file() {
  if [ "${OS}" = "Linux" ] && [ -n "${SUDO_USER:-}" ]; then
    chown "${SUDO_USER}:${SUDO_USER}" "$1"
  fi
}

# --------------------------------------------------------------------------
# Linux: systemd + system PostgreSQL (run as root)
# --------------------------------------------------------------------------

setup_linux() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Error: on Linux, run this script with sudo:"
    echo "  sudo ./setup.sh"
    exit 1
  fi

  echo "[1/4] Checking prerequisites..."
  if ! require_cmd go; then
    echo "  Error: Go is not installed or not in PATH."
    echo "  Install Go from https://go.dev/dl/ then re-run this script."
    exit 1
  fi
  echo "      Go found: $(go version | awk '{print $3}')"

  echo "[2/4] Starting PostgreSQL..."
  local started=""
  if systemctl start postgresql 2>/dev/null; then started=1; fi
  # Also start a versioned cluster unit (e.g. postgresql@18-main) if present.
  local unit
  unit="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
          | awk '/^postgresql@[0-9]+-main\.service/{print $1; exit}')"
  if [ -n "${unit}" ] && systemctl start "${unit}" 2>/dev/null; then started=1; fi
  if [ -z "${started}" ]; then
    echo "  Error: could not start PostgreSQL. Is the 'postgresql' service installed?"
    echo "         Install it with: sudo apt update && sudo apt install -y postgresql"
    exit 1
  fi
  echo "      PostgreSQL is running."
}

# --------------------------------------------------------------------------
# macOS: Homebrew PostgreSQL (run as the normal user, NOT root)
# --------------------------------------------------------------------------

setup_macos() {
  if [ "$(id -u)" -eq 0 ]; then
    echo "Error: on macOS, run this script WITHOUT sudo:"
    echo "  ./setup.sh"
    echo "  (Homebrew refuses to run as root, and its PostgreSQL runs as your user.)"
    exit 1
  fi

  if ! require_cmd brew; then
    echo "  Error: Homebrew is required on macOS. Install it from https://brew.sh then re-run."
    exit 1
  fi

  echo "[1/4] Checking prerequisites..."
  if ! require_cmd go; then
    echo "      Go not found — installing via Homebrew..."
    brew install go
  fi
  echo "      Go found: $(go version | awk '{print $3}')"

  # Find an installed postgresql formula, or install one.
  local pg_formula
  pg_formula="$(brew list --formula 2>/dev/null | grep -E '^postgresql(@[0-9.]+)?$' | sort -V | tail -1 || true)"
  if [ -z "${pg_formula}" ]; then
    echo "      Installing postgresql@16..."
    brew install postgresql@16
    pg_formula="postgresql@16"
  fi
  echo "      Using PostgreSQL formula: ${pg_formula}"

  # Versioned formulae (postgresql@NN) are keg-only, so put their client
  # tools (psql, createuser, createdb, pg_isready) on PATH.
  local pg_bin
  pg_bin="$(brew --prefix "${pg_formula}")/bin"
  export PATH="${pg_bin}:${PATH}"

  echo "[2/4] Starting PostgreSQL service..."
  brew services start "${pg_formula}" >/dev/null
  echo "      Waiting for PostgreSQL to accept connections..."
  local ready=""
  local _
  for _ in $(seq 1 30); do
    if pg_isready -q 2>/dev/null; then ready=1; break; fi
    sleep 1
  done
  if [ -z "${ready}" ]; then
    echo "  Error: PostgreSQL did not become ready. Check: brew services list"
    exit 1
  fi
  echo "      PostgreSQL is running."
}

# --------------------------------------------------------------------------
# Shared: role, database and extension
# --------------------------------------------------------------------------

setup_db() {
  echo "[3/4] Creating role '${DB_USER}' and database '${DB_NAME}'..."
  local db_exists="" has_data=""
  if psql_admin postgres "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -qx 1; then
    db_exists=1
    if psql_admin "${DB_NAME}" "SELECT 1 FROM users LIMIT 1" 2>/dev/null | grep -qx 1; then
      has_data=1
    fi
  fi

  # New secrets for existing data would lock 2FA users out and make every
  # stored credential unreadable, so stop before changing anything.
  if [ -n "${has_data}" ] && [ ! -f "${ENV_FILE}" ]; then
    echo "  Error: database '${DB_NAME}' already holds data, but ${ENV_FILE} is missing."
    echo "  Copy the .env of the install that created that data (it holds JWT_SECRET,"
    echo "  ENCRYPTION_KEY and DATABASE_URL) to ${ENV_FILE} and re-run this script."
    echo "  To start over with an empty database instead, drop it first:"
    if [ "${OS}" = "Linux" ]; then
      echo "    sudo -u postgres dropdb ${DB_NAME}"
    else
      echo "    dropdb ${DB_NAME}"
    fi
    exit 1
  fi

  if psql_admin postgres "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -qx 1; then
    if [ -f "${ENV_FILE}" ]; then
      echo "      role '${DB_USER}' already exists, skipping."
    else
      # The new .env needs the password, and the old one cannot be read back.
      DB_PASS="$(openssl rand -hex 24)"
      psql_admin postgres "ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';"
      echo "      role '${DB_USER}' already exists; set a new random password for it."
    fi
  else
    DB_PASS="$(openssl rand -hex 24)"
    psql_admin postgres "CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';"
    echo "      created role '${DB_USER}' with a random password."
  fi
  if [ -n "${db_exists}" ]; then
    echo "      database '${DB_NAME}' already exists, skipping."
  else
    psql_admin postgres "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
  fi

  echo "[4/4] Enabling uuid-ossp extension..."
  psql_admin "${DB_NAME}" 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' >/dev/null 2>&1 || true
  echo "      Done."
}

# --------------------------------------------------------------------------
# Shared: .env generation and build
# --------------------------------------------------------------------------

setup_env() {
  echo "[env] Setting up .env file..."
  if [ -f "${ENV_FILE}" ]; then
    local url updated current
    url="$(database_url)"
    if [ -n "${DB_PASS}" ] && current="$(env_value DATABASE_URL)" && [ -n "${current}" ] &&
       ! managed_url "${current}"; then
      # DATABASE_URL points at another database: keep it.
      echo "      .env already exists; its DATABASE_URL is not the local '${DB_USER}' role and"
      echo "      '${DB_NAME}' database this script set up, so it was left unchanged."
      echo "      To use the local database instead, set in .env:"
      echo "        DATABASE_URL=${url}"
    elif [ -n "${DB_PASS}" ]; then
      # The role was just created, so the stored DATABASE_URL is stale.
      updated="$(sed -E "s|^([[:space:]]*(export[[:space:]]+)?)DATABASE_URL[[:space:]]*=.*|\1DATABASE_URL=${url}|" "${ENV_FILE}")"
      if ! grep -qF "DATABASE_URL=${url}" <<<"${updated}"; then
        updated+=$'\n'"DATABASE_URL=${url}"
      fi
      write_env_file "${updated}"
      echo "      .env already exists; set its DATABASE_URL to the new role password."
      echo "      If DATABASE_URL is also set outside .env (e.g. in a systemd unit), that"
      echo "      value wins: copy the new one from .env there."
    else
      echo "      .env already exists, skipping."
    fi
    return
  fi
  # Generate every value before writing, so a failure leaves no partial .env.
  local jwt_secret enc_key content
  jwt_secret="$(openssl rand -hex 32)"
  enc_key="$(openssl rand -hex 32)"
  content="$(sed -e "s|^DATABASE_URL=.*|DATABASE_URL=$(database_url)|" \
                 -e "s|^JWT_SECRET=.*|JWT_SECRET=${jwt_secret}|" \
                 -e "s|^# ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${enc_key}|" \
                 "${SCRIPT_DIR}/.env.example")"
  if ! grep -q '^ENCRYPTION_KEY=' <<<"${content}"; then
    content+=$'\n'"ENCRYPTION_KEY=${enc_key}"
  fi
  write_env_file "${content}"
  echo "      .env created (mode 600) with a random JWT_SECRET, ENCRYPTION_KEY and"
  echo "      database password. Never change ENCRYPTION_KEY once credentials are saved."
}

build_binaries() {
  echo "[build] Building server binary..."
  ( cd "${SCRIPT_DIR}" && CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o "${SCRIPT_DIR}/server" ./cmd/server )
  own_file "${SCRIPT_DIR}/server"
  echo "        Built: ${SCRIPT_DIR}/server"

  echo "[build] Building and installing pk CLI..."
  local bin_dir
  if [ "${OS}" = "Darwin" ]; then
    bin_dir="$(brew --prefix)/bin"   # user-writable, on PATH
  else
    bin_dir="/usr/local/bin"
  fi
  ( cd "${SCRIPT_DIR}" && CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o "${SCRIPT_DIR}/pk" ./cmd/pk )
  install -m 0755 "${SCRIPT_DIR}/pk" "${bin_dir}/pk"
  rm -f "${SCRIPT_DIR}/pk"
  echo "        Installed: ${bin_dir}/pk"
}

print_done() {
  echo ""
  echo "Setup complete!"
  echo ""
  echo "  Start the server (auto-loads .env):"
  echo "    ./server"
  echo ""
  echo "  Then open http://localhost:1338 and follow the first-launch prompt to"
  echo "  create your admin account."
  echo ""
  echo "  Authenticate the CLI:"
  echo "    pk login"
  echo ""
  echo "  Pipe tool output to a host:"
  echo "    <tool> | pk --target <ip>"
  echo "    pk --target <ip> --run \"<command>\""
  echo ""
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

if ! require_cmd openssl; then
  echo "Error: openssl is required to generate secrets. Install it and re-run."
  exit 1
fi
check_env_file

case "${OS}" in
  Linux)  setup_linux ;;
  Darwin) setup_macos ;;
  *)
    echo "Unsupported OS: ${OS}"
    echo "This script supports Linux (Debian/Kali/Ubuntu) and macOS."
    exit 1
    ;;
esac

setup_db
setup_env
build_binaries
print_done
