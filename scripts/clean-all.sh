#!/usr/bin/env bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo -e "${YELLOW}====================================================${NC}"
echo -e "${YELLOW}   SARAL — Complete Cleanup & Reset Script         ${NC}"
echo -e "${YELLOW}====================================================${NC}"

# 1. Stop and remove all SARAL Docker containers & volumes
echo -e "\n${BLUE}[1/4] Stopping and removing SARAL containers & volumes...${NC}"
docker compose -f infra/compose/full24.yml down -v --remove-orphans 2>/dev/null || true
docker compose -f infra/compose/poc15.yml down -v --remove-orphans 2>/dev/null || true

# Also catch any remaining containers named 'saral'
STRAY_CONTAINERS=$(docker ps -a -q --filter "name=saral")
if [ -n "$STRAY_CONTAINERS" ]; then
  echo "Removing stray SARAL containers..."
  docker rm -f $STRAY_CONTAINERS 2>/dev/null || true
fi

# Remove dangling SARAL volumes (node vaults, postgres data)
STRAY_VOLUMES=$(docker volume ls -q --filter "name=saral" --filter "name=node_")
if [ -n "$STRAY_VOLUMES" ]; then
  echo "Removing SARAL data volumes..."
  docker volume rm -f $STRAY_VOLUMES 2>/dev/null || true
fi
echo -e "${GREEN}✓ Docker containers and volumes removed.${NC}"

# 2. Clear data/ folder files
echo -e "\n${BLUE}[2/4] Clearing data/ storage files...${NC}"
mkdir -p data
if [ -f data/saral_auth_store.json ]; then
  rm -f data/saral_auth_store.json
fi
rm -f data/*.json 2>/dev/null || true
echo -e "${GREEN}✓ data/ folder cleared.${NC}"

# 3. Clean build artifacts and dist directories
echo -e "\n${BLUE}[3/4] Cleaning build artifacts...${NC}"
npm run clean 2>/dev/null || true
echo -e "${GREEN}✓ Build artifacts cleaned.${NC}"

# 4. Reset PostgreSQL database tables using Prisma
echo -e "\n${BLUE}[4/4] Resetting PostgreSQL database tables...${NC}"
if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
  (cd apps/auth-server && npx prisma db push --force-reset --accept-data-loss)
  echo -e "${GREEN}✓ PostgreSQL database tables dropped and recreated clean.${NC}"
else
  echo -e "${YELLOW}⚠️  PostgreSQL on localhost:5432 is not currently running. Skipping DB reset.${NC}"
fi

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN}✓ SARAL project has been completely wiped clean!    ${NC}"
echo -e "${GREEN}====================================================${NC}"

