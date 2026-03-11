#!/bin/bash
# Idempotent setup of all skwaq dependencies.
# Safe to run multiple times.
set -e

echo "=== Skwaq Dependency Setup ==="

# Java (required for Ghidra)
if ! java -version 2>/dev/null | grep -q "version"; then
    echo "[install] Java 21..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq openjdk-21-jdk
else
    echo "[ok] Java $(java -version 2>&1 | head -1 | awk -F'"' '{print $2}')"
fi

# Ghidra
GHIDRA_VERSION="11.3"
GHIDRA_DIR="/opt/ghidra_${GHIDRA_VERSION}_PUBLIC"
if [ -d "$GHIDRA_DIR" ] && [ -f "$GHIDRA_DIR/support/analyzeHeadless" ]; then
    echo "[ok] Ghidra $GHIDRA_VERSION at $GHIDRA_DIR"
else
    echo "[install] Ghidra $GHIDRA_VERSION..."
    GHIDRA_ZIP="/tmp/ghidra_${GHIDRA_VERSION}.zip"
    if [ ! -f "$GHIDRA_ZIP" ]; then
        wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20250205.zip" -O "$GHIDRA_ZIP"
    fi
    sudo unzip -q -o "$GHIDRA_ZIP" -d /opt/
    echo "[ok] Ghidra $GHIDRA_VERSION installed"
fi
sudo ln -sf "$GHIDRA_DIR" /opt/ghidra

# Export for current session
export GHIDRA_INSTALL_DIR=/opt/ghidra

# Semgrep (optional)
if command -v semgrep &>/dev/null; then
    echo "[ok] Semgrep $(semgrep --version 2>/dev/null)"
else
    echo "[skip] Semgrep not installed (optional). Install: pip install semgrep"
fi

# Python (for angr, optional)
if command -v python3 &>/dev/null; then
    echo "[ok] Python $(python3 --version 2>&1 | awk '{print $2}')"
else
    echo "[skip] Python3 not found (optional, needed for angr)"
fi

echo ""
echo "Setup complete. Add to your shell profile:"
echo "  export GHIDRA_INSTALL_DIR=/opt/ghidra"
