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
echo -e "${CYAN}${BOLD}   SARAL Protocol V3 — Launch Development Environment                 ${NC}"
echo -e "${CYAN}======================================================================${NC}"

# Check Docker backend nodes
RUNNING_NODES=$(docker ps --filter "name=saral-prod-coord-foundation" -q)
if [ -z "$RUNNING_NODES" ]; then
  echo -e "\n${YELLOW}Docker backend nodes are not running. Starting Docker containers...${NC}"
  docker compose -f infra/compose/full24.yml up -d \
    node-f1 node-f2 node-f3 node-f4 node-f5 \
    node-p1 node-p2 node-p3 node-p4 node-p5 \
    node-r1 node-r2 node-r3 node-r4 node-r5 \
    coordinator-foundation coordinator-public coordinator-private \
    verifier-foundation verifier-public verifier-private 2>/dev/null || true
  sleep 3
fi

# Check Postgres
if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
  echo -e "${YELLOW}⚠️  PostgreSQL is not running on port 5432. Make sure PostgreSQL is started.${NC}"
fi

echo -e "\n${GREEN}✓ Starting Node.js Auth Server (:3001) & React Vite Frontend (:5173)...${NC}"
echo -e "   • Dashboard: ${CYAN}http://localhost:5173/wallet${NC}"
echo -e "   • API:       ${CYAN}http://localhost:3001${NC}\n"

exec npm run dev

