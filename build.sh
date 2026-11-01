#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_BIN="${SCRIPT_DIR}/imessage-agy-daemon"
INSTALL_DIR="$HOME/.local/bin"

chmod +x "${SCRIPT_DIR}/sync_workspaces.sh" "${SCRIPT_DIR}/jail/.agents/scripts/pre_tool_guard.py"
"${SCRIPT_DIR}/sync_workspaces.sh"

echo "Compiling native imessage-agy-daemon (arm64 Objective-C with ARC)..."
clang -O2 -fobjc-arc -Wall -Wextra \
    -framework Foundation \
    -lsqlite3 \
    "${SCRIPT_DIR}/daemon.m" \
    -o "${OUTPUT_BIN}"

echo "Installing to ${INSTALL_DIR}/imessage-agy-daemon..."
mkdir -p "${INSTALL_DIR}"
cp -f "${OUTPUT_BIN}" "${INSTALL_DIR}/imessage-agy-daemon"

CODESIGN_ID="${CODESIGN_ID:-com.antigravity.imessage-agy-daemon}"
echo "Code-signing binaries with ad-hoc identity '${CODESIGN_ID}'..."
codesign -s - --identifier "${CODESIGN_ID}" -f "${OUTPUT_BIN}"
codesign -s - --identifier "${CODESIGN_ID}" -f "${INSTALL_DIR}/imessage-agy-daemon"

echo "Verifying signature on installed binary:"
codesign -dvvv "${INSTALL_DIR}/imessage-agy-daemon"

echo ""
echo "✅ Compilation and workspace deployment successful!"
echo "Binary paths:"
echo "  Project:   ${OUTPUT_BIN}"
echo "  Installed: ${INSTALL_DIR}/imessage-agy-daemon"
