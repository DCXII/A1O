#!/bin/bash

# A1OSINT - Professional OSINT Platform Installation Script
# This script handles all necessary dependencies.

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}--------------------------------------------------${NC}"
echo -e "${BLUE}          A1OSINT - Installation Script           ${NC}"
echo -e "${BLUE}--------------------------------------------------${NC}"

# Check for Python
if ! command -v python3 &> /dev/null
then
    echo -e "${RED}[ERROR] python3 is not installed. Please install it and try again.${NC}"
    exit 1
fi

# Check for Pip
if ! command -v pip3 &> /dev/null
then
    echo -e "${RED}[ERROR] pip3 is not installed. Please install it and try again.${NC}"
    exit 1
fi

echo -e "${GREEN}[INFO] Installing Python dependencies...${NC}"
# Use --break-system-packages if on an OS that requires it (like newer Kali/Debian)
# Otherwise standard install.
if pip3 install --break-system-packages -r requirements.txt 2>/dev/null; then
    echo -e "${GREEN}[OK] Requirements installed successfully with --break-system-packages.${NC}"
else
    if pip3 install -r requirements.txt; then
        echo -e "${GREEN}[OK] Requirements installed successfully.${NC}"
    else
        echo -e "${RED}[ERROR] Failed to install requirements. Please check your internet connection.${NC}"
        exit 1
    fi
fi

# Optional: Check for Ollama
if ! command -v ollama &> /dev/null
then
    echo -e "${BLUE}[INFO] Ollama not found. If you want local AI, install it from ollama.com${NC}"
else
    echo -e "${GREEN}[OK] Ollama detected. Local AI mode (--ai ollama) is ready.${NC}"
fi

echo -e "${GREEN}--------------------------------------------------${NC}"
echo -e "${GREEN}           Installation Complete!                 ${NC}"
echo -e "${GREEN}    Run with: python3 osint.py --help             ${NC}"
echo -e "${GREEN}--------------------------------------------------${NC}"
