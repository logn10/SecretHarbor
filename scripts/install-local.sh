#!/bin/bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Updating SecretHarbor binaries..."
rm -f "$REPO_DIR/bin/shb" "$REPO_DIR/bin/secretharbor"

if [ -f "$REPO_DIR/bin/shb-v0.4.0" ]; then
    cp "$REPO_DIR/bin/shb-v0.4.0" "$REPO_DIR/bin/shb"
    cp "$REPO_DIR/bin/secretharbor-v0.4.0" "$REPO_DIR/bin/secretharbor"
else
    go build -o "$REPO_DIR/bin/shb" "$REPO_DIR/cmd/shb"
    go build -o "$REPO_DIR/bin/secretharbor" "$REPO_DIR/cmd/secretharbor"
fi

if [ "$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
    codesign -s - -f "$REPO_DIR/bin/shb"
    codesign -s - -f "$REPO_DIR/bin/secretharbor"
fi

mkdir -p "$HOME/.local/bin"
ln -sf "$REPO_DIR/bin/shb" "$HOME/.local/bin/shb"
ln -sf "$REPO_DIR/bin/secretharbor" "$HOME/.local/bin/secretharbor"

echo "✓ Successfully installed SecretHarbor to $HOME/.local/bin/shb"
"$HOME/.local/bin/shb" version

