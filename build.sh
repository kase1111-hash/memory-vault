#!/bin/bash
#
# Memory Vault - Linux/macOS Build Script
#

set -e

echo "========================================"
echo "  Memory Vault - Build Script"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

ok() { echo -e "${GREEN}[OK]${NC} $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check for Python
if ! command -v python3 &> /dev/null; then
    err "Python 3 not found. Please install Python 3.7+ from https://python.org"
fi

PYVER=$(python3 --version 2>&1 | awk '{print $2}')
ok "Found Python $PYVER"

# Check Python version is 3.7+
PYMAJOR=$(echo "$PYVER" | cut -d. -f1)
PYMINOR=$(echo "$PYVER" | cut -d. -f2)
if [ "$PYMAJOR" -lt 3 ] || ([ "$PYMAJOR" -eq 3 ] && [ "$PYMINOR" -lt 7 ]); then
    err "Python 3.7+ required, found $PYVER"
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo ""
    echo "[1/4] Creating virtual environment..."
    python3 -m venv venv || err "Failed to create virtual environment"
    ok "Virtual environment created"
else
    ok "Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "[2/4] Activating virtual environment..."
source venv/bin/activate
ok "Activated"

# Upgrade pip
echo ""
echo "[3/4] Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1
ok "Pip upgraded"

# Install dependencies
echo ""
echo "[4/4] Installing dependencies..."
if [ -f "pyproject.toml" ]; then
    pip install -e ".[dev]" || err "Failed to install package"
    ok "Installed with pip (editable mode + dev dependencies)"
else
    pip install -r requirements.txt || err "Failed to install dependencies"
    ok "Installed from requirements.txt"
fi

# Verify installation
echo ""
echo "========================================"
echo "  Verifying Installation"
echo "========================================"

python3 -c "from vault import MemoryVault; print('[OK] vault module imports successfully')" 2>/dev/null || \
python3 -c "from memory_vault import vault; print('[OK] memory_vault module imports successfully')"

python3 -c "import nacl; print('[OK] PyNaCl crypto library ready')"

# Run quick tests if pytest available
if python3 -c "import pytest" 2>/dev/null; then
    echo ""
    echo "Running quick smoke tests..."
    pytest tests/ -q --tb=no 2>/dev/null && ok "All tests passed" || echo "[WARN] Some tests failed (may need boundary daemon)"
fi

# Show completion message
echo ""
echo "========================================"
echo "  Build Complete!"
echo "========================================"
echo ""
echo "To use Memory Vault:"
echo "  1. Activate the environment: source venv/bin/activate"
echo "  2. Run CLI: python -m memory_vault.cli --help"
echo "     Or:      python cli.py --help"
echo ""
echo "Quick start:"
echo "  python cli.py create-profile my-profile --key-source HumanPassphrase"
echo "  python cli.py store --content \"test\" --classification 1 --profile my-profile"
echo ""
