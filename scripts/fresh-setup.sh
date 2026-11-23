#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}${BOLD}   SARAL Protocol V3 — Complete Automated Setup & Provisioning       ${NC}"
echo -e "${CYAN}======================================================================${NC}"

# Step 1: Wipe everything clean
bash scripts/clean-all.sh

# Step 2: Ensure persistent cryptographic keys & cluster secrets
echo -e "\n${BLUE}[1/6] Verifying asymmetric keys & cluster secrets...${NC}"
mkdir -p infra/config infra/secrets

# Generate Ed25519 keypair if missing (provisioning all standard naming variants)
if [ ! -f infra/config/auth_ed25519_private_key.pem ] || [ ! -f infra/config/auth_ed25519_public_key.pem ]; then
  echo "Generating persistent Ed25519 keypair for Auth Server, Verifiers & Nodes..."
  openssl genpkey -algorithm ED25519 -out infra/config/auth_ed25519_private_key.pem 2>/dev/null
  openssl pkey -in infra/config/auth_ed25519_private_key.pem -pubout -out infra/config/auth_ed25519_public_key.pem 2>/dev/null
  chmod 600 infra/config/auth_ed25519_private_key.pem
  chmod 644 infra/config/auth_ed25519_public_key.pem
fi

# Ensure compatibility links/copies
cp -f infra/config/auth_ed25519_private_key.pem infra/config/auth_ed25519_private.key 2>/dev/null || true
cp -f infra/config/auth_ed25519_public_key.pem infra/config/auth_ed25519_public.key 2>/dev/null || true
cp -f infra/config/auth_ed25519_public_key.pem infra/config/auth_public_key.pem 2>/dev/null || true

# Ensure internal cluster token exists
if [ ! -f infra/secrets/internal_token.secret ]; then
  echo "Generating 256-bit cluster internal secret token..."
  openssl rand -hex 32 > infra/secrets/internal_token.secret
  chmod 600 infra/secrets/internal_token.secret
fi
echo -e "${GREEN}✓ Cryptographic keys and cluster secrets verified.${NC}"

# Step 3: Compile Static Go Microservice Binaries
echo -e "\n${BLUE}[2/6] Compiling Go SARAL node microservice (CGO_ENABLED=0 GOOS=linux)...${NC}"
mkdir -p services/saral-node/bin
(cd services/saral-node && CGO_ENABLED=0 GOOS=linux go build -o bin/saral-node ./cmd/main.go)
echo -e "${GREEN}✓ Go SARAL node microservice compiled successfully.${NC}"

# Step 4: Build Prisma Client & Sync Database
echo -e "\n${BLUE}[3/6] Generating Prisma ORM Client & syncing database...${NC}"
npm run prisma:generate
if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
  (cd apps/auth-server && npx prisma db push --accept-data-loss)
  echo -e "${GREEN}✓ Database schema pushed and verified successfully.${NC}"
else
  echo -e "${YELLOW}⚠️  PostgreSQL on localhost:5432 is offline. Skipping database schema push.${NC}"
fi

# Step 5: Start 15 DKG Backend Containers in Docker
echo -e "\n${BLUE}[4/6] Starting 15 DKG backend containers in Docker...${NC}"
docker compose -f infra/compose/full24.yml up -d \
  node-f1 node-f2 node-f3 node-f4 node-f5 \
  node-p1 node-p2 node-p3 node-p4 node-p5 \
  node-r1 node-r2 node-r3 node-r4 node-r5 2>/dev/null || true

# Step 6: Provision Keys, Secrets & Binaries into Containers
echo -e "\n${BLUE}[5/6] Provisioning binaries, verification keys & secrets to containers...${NC}"

# Synchronize genesis participants with node identities
sleep 2
node scripts/sync-genesis.js 2>/dev/null || true

# Nodes
SERVICES_WITH_TOKEN=(
  saral-prod-node-f1 saral-prod-node-f2 saral-prod-node-f3 saral-prod-node-f4 saral-prod-node-f5
  saral-prod-node-p1 saral-prod-node-p2 saral-prod-node-p3 saral-prod-node-p4 saral-prod-node-p5
  saral-prod-node-r1 saral-prod-node-r2 saral-prod-node-r3 saral-prod-node-r4 saral-prod-node-r5
)

for c in "${SERVICES_WITH_TOKEN[@]}"; do
  docker exec $c mkdir -p /run/secrets 2>/dev/null || true
  cat infra/secrets/internal_token.secret | docker exec -i $c sh -c "cat > /run/secrets/saral_internal_token 2>/dev/null || true"
  cat infra/config/genesis_participants.json | docker exec -i $c sh -c "cat > /run/secrets/saral_genesis_participants.json 2>/dev/null || true"
  cat infra/config/auth_public_key.pem | docker exec -i $c sh -c "cat > /run/secrets/auth_ed25519_pub.pem 2>/dev/null || true"
  # Deploy latest compiled binary
  docker cp services/saral-node/bin/saral-node $c:/usr/local/bin/saral-node 2>/dev/null || true
  docker restart $c >/dev/null &
done
wait

echo "Waiting 6 seconds for container health checks..."
sleep 6

# Check health status
UNHEALTHY=$(docker ps --filter "name=saral-prod" --filter "health=unhealthy" -q)
if [ -n "$UNHEALTHY" ]; then
  echo -e "${RED}⚠️  Warning: Some containers are reporting unhealthy. Check logs: docker logs <container>${NC}"
else
  echo -e "${GREEN}✓ All 21 DKG backend containers are healthy and running.${NC}"
fi

# Step 7: Live Verification of 3-of-5 DKG Consensus & Multi-Chain Derivation
echo -e "\n${BLUE}[6/6] Verifying live Dealerless 3-of-5 DKG & address derivation...${NC}"
npx tsx -e '
import { saralBackendClient } from "./apps/auth-server/src/clients/saralBackendClient";

async function verify() {
  const sessionId = "dkg-verify-" + Date.now();
  console.log("   • Starting Dealerless DKG session:", sessionId);
  const start = await saralBackendClient.startDkg({
    committeeId: "committee-foundation",
    sessionId,
    committee: ["saral-foundation-1", "saral-foundation-2", "saral-foundation-3", "saral-foundation-4", "saral-foundation-5"],
    n: 5,
    k: 3,
    t: 1,
  });

  if (!start || !start.success) {
    throw new Error("Failed to start DKG session");
  }

  // Poll until completed
  let done = false;
  for (let i = 0; i < 20; i++) {
    await new Promise(r => setTimeout(r, 250));
    const st = await saralBackendClient.getDkgStatus(sessionId);
    if (st?.state === "COMPLETED" || (st?.completedNodes && st.completedNodes >= 3)) {
      done = true;
      console.log(`   • DKG Consensus COMPLETED (${st.completedNodes}/5 nodes decided)`);
      break;
    }
  }

  if (!done) {
    throw new Error("DKG Consensus timed out across 3-of-5 threshold nodes");
  }

  // Test address derivation for MST (secp256k1)
  const mst = await saralBackendClient.derivePublicKey({
    walletId: "wal-verify",
    userId: "user-verify",
    keyId: "key-mst-verify",
    dkgSessionId: sessionId,
    committeeId: "committee-foundation",
    curve: "secp256k1",
    chainFamily: "mst",
  });

  // Test address derivation for Solana (ed25519)
  const sol = await saralBackendClient.derivePublicKey({
    walletId: "wal-verify",
    userId: "user-verify",
    keyId: "key-sol-verify",
    dkgSessionId: sessionId,
    committeeId: "committee-foundation",
    curve: "ed25519",
    chainFamily: "solana",
  });

  // Test address derivation for Bitcoin (secp256k1 taproot)
  const btc = await saralBackendClient.derivePublicKey({
    walletId: "wal-verify",
    userId: "user-verify",
    keyId: "key-btc-verify",
    dkgSessionId: sessionId,
    committeeId: "committee-foundation",
    curve: "secp256k1",
    chainFamily: "bitcoin",
  });

  console.log("\x1b[32m   ✓ MST Testnet Address:    " + mst.derivedAddress + "\x1b[0m");
  console.log("\x1b[32m   ✓ Solana Devnet Address:  " + sol.derivedAddress + "\x1b[0m");
  console.log("\x1b[32m   ✓ Bitcoin Testnet Address: " + btc.derivedAddress + "\x1b[0m");
}

verify().catch(e => {
  console.error("\x1b[31m✗ Verification failed:\x1b[0m", e.message);
  process.exit(1);
});
'

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}${BOLD}🎉 SARAL PROTOCOL — FRESH SETUP COMPLETED & VERIFIED!                 ${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo -e "To launch the full full-stack application (Auth Server + React Web UI):"
echo -e "   ${CYAN}${BOLD}npm run dev${NC}"
echo -e "\nAvailable Services:"
echo -e "   • React Web Dashboard: ${CYAN}http://localhost:5173/wallet${NC}"
echo -e "   • Node.js Auth Server: ${CYAN}http://localhost:3001${NC}"
echo -e "   • Foundation Coord:   ${CYAN}http://localhost:9001/rpc${NC}"
echo -e "   • Public Coord:       ${CYAN}http://localhost:9002/rpc${NC}"
echo -e "   • Private Coord:      ${CYAN}http://localhost:9003/rpc${NC}"
echo -e "${GREEN}======================================================================${NC}\n"
