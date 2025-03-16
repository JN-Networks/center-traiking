#!/bin/bash

# ----- Colors -----
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ----- Logo -----
echo ""
echo -e "${CYAN}"
echo "   ____            _               _______        _ _    _             "
echo "  / ___| ___ _ __ | |_ ___ _ __   |__   __|      (_) |  (_)            "
echo " | |  _ / _ \\ '_ \\| __/ _ \\ '__|     | |_ __ __ _ _| | ___ _ __   __ _ "
echo " | |_| |  __/ | | | ||  __/ |        | | '__/ _\` | | |/ / | '_ \\ / _\` |"
echo "  \\____|\\___|_| |_|\\__\\___|_|        | | | | (_| | |   <| | | | | (_| |"
echo "                                     |_|_|  \\__,_|_|_|\\_\\_|_| |_|\\__, |"
echo "                                                                  __/ |"
echo "                                                                 |___/ "
echo -e "${NC}"
echo -e "CopyRight © Justin Nolte (JN-Networks) 2025-$(date +%Y)"
echo "------------------------------------------------------------"
echo ""

# ----- Consent -----
read -p "Do you agree to install Python, ChromeDriver, and required packages? (y/n): " consent

if [[ "$consent" != "y" ]]; then
  echo -e "${RED}Installation cancelled.${NC}"
  exit 1
fi

# ----- Spinner Function -----
spin() {
  sp='/-\\|'
  printf ' '
  while kill -0 $1 2>/dev/null; do
    printf "\b${sp:i++%${#sp}:1}"
    sleep 0.1
  done
}

# ----- Python Check -----
echo -e "${CYAN}[*] Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
  echo -e "${GREEN}[+] Installing Python3...${NC}"
  sudo apt update &> /dev/null
  (sudo apt install -y python3 &> /dev/null) &
  spin $!
else
  echo -e "${GREEN}[+] Python3 already installed.${NC}"
fi

# ----- Pip Check -----
echo -e "${CYAN}[*] Checking pip installation...${NC}"
if ! command -v pip3 &> /dev/null; then
  echo -e "${GREEN}[+] Installing pip3...${NC}"
  (sudo apt install -y python3-pip &> /dev/null) &
  spin $!
else
  echo -e "${GREEN}[+] Pip3 already installed.${NC}"
fi

# ----- Install Python Requirements -----
echo -e "${CYAN}[*] Installing Python requirements...${NC}"
(pip3 install -r requirements.txt &> /dev/null) &
spin $!

# ----- Done -----
echo ""
echo -e "${GREEN}✅ Installation complete!${NC}"
echo ""
echo -e "You can now run the tool with: ${CYAN}python3 main.py${NC}"
echo ""
echo -e "Need help? Join our Discord: ${CYAN}https://discord.gg/4p6AfbnpXv${NC}"
echo ""

exit 0
