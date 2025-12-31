@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   Memory Vault - Windows Build Script
echo ========================================
echo.

:: Check for Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

:: Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [OK] Found Python %PYVER%

:: Create virtual environment if it doesn't exist
if not exist "venv" (
    echo.
    echo [1/3] Creating virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created
) else (
    echo [OK] Virtual environment already exists
)

:: Activate virtual environment
echo.
echo [2/3] Activating virtual environment...
call venv\Scripts\activate.bat

:: Install dependencies
echo.
echo [3/3] Installing dependencies...
pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

:: Verify installation
echo.
echo ========================================
echo   Verifying Installation
echo ========================================
python -c "from memory_vault import vault; print('[OK] memory_vault module imports successfully')" 2>nul
if %errorlevel% neq 0 (
    :: Try alternate import for flat structure
    python -c "import vault; print('[OK] vault module imports successfully')"
)

python -c "import nacl; print('[OK] PyNaCl crypto library ready')"

:: Show CLI help
echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo To use Memory Vault:
echo   1. Activate the environment: venv\Scripts\activate
echo   2. Run CLI: python -m memory_vault.cli --help
echo      Or:      python cli.py --help
echo.
echo Quick start:
echo   python cli.py create-profile my-profile --key-source HumanPassphrase
echo   python cli.py store --content "test" --classification 1 --profile my-profile
echo.

pause
