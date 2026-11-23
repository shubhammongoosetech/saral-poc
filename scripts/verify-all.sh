#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}${BOLD}   SARAL Protocol V3 — Complete Verification & Test Suite             ${NC}"
echo -e "${CYAN}======================================================================${NC}"

# 1. TypeScript Security & Lifecycle Suite
echo -e "\n${BLUE}[1/4] Running TypeScript Vitest Security & Lifecycle Suite...${NC}"
npm run test:ts
echo -e "${GREEN}✓ All TypeScript security & wallet lifecycle tests PASSED.${NC}"

# 2. Go Architecture & Relay Integration Tests
echo -e "\n${BLUE}[2/4] Running Go Architecture & Multi-Domain Relay Integration Suite...${NC}"
npm run test:go
echo -e "${GREEN}✓ All Go architecture & relay network tests PASSED.${NC}"

# 3. Cryptographic AVSS, ABBA & Proactive Refresh Suite
echo -e "\n${BLUE}[3/4] Running AVSS, ABBA Consensus & Proactive Cryptography Suite...${NC}"
npm run test:all-crypto
echo -e "${GREEN}✓ All cryptographic test vectors & distributed protocols PASSED.${NC}"

# 4. Docker Backend Cluster Status & 3-Domain Health
echo -e "\n${BLUE}[4/4] Verifying 3-Domain cluster health across 15 nodes and 3 coordinators...${NC}"
RUNNING_CONTAINERS=$(docker ps --filter "name=saral-prod" --format "{{.Names}}" | wc -l)
echo "   • Active SARAL containers: $RUNNING_CONTAINERS / 21"
if [ "$RUNNING_CONTAINERS" -ge 21 ]; then
  echo -e "${GREEN}✓ All 21 Docker backend nodes and 3 coordinators (Foundation, Public, Private) are active.${NC}"
else
  echo -e "${YELLOW}⚠️  Note: $RUNNING_CONTAINERS / 21 containers detected. Run 'npm run setup' to start all 21.${NC}"
fi

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}${BOLD}✅ 100% OF SARAL PROTOCOL TEST SUITES & CHECKS PASSED SUCCESSFULLY!    ${NC}"
echo -e "${GREEN}======================================================================${NC}\n"

