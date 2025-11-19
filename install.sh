#!/usr/bin/env bash
# Simple installer for lootserve
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/lootserve.py"
TARGET="/usr/local/bin/lootserve"

if [[ ! -f "$SRC" ]]; then
    echo "Error: lootserve.py not found in ${SCRIPT_DIR}" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (e.g., sudo ./install.sh)" >&2
    exit 1
fi

# Ensure the script is executable
chmod +x "$SRC"

# Install into /usr/local/bin
install -m 0755 "$SRC" "$TARGET"

echo "Installed lootserve to: $TARGET"
echo "Now you can run:"
echo "  lootserve -d ."
