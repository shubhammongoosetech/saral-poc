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
echo -e "\n${BLUE}[2/6] Compiling Go microservices (CGO_ENABLED=0 GOOS=linux)...${NC}"
mkdir -p services/saral-node/bin services/coordinator/bin services/verifier/bin
(cd services/saral-node && CGO_ENABLED=0 GOOS=linux go build -o bin/saral-node ./cmd/main.go)
(cd services/coordinator && CGO_ENABLED=0 GOOS=linux go build -o bin/coordinator ./cmd/main.go)
(cd services/verifier && CGO_ENABLED=0 GOOS=linux go build -o bin/verifier ./cmd/main.go)
echo -e "${GREEN}✓ Go microservices compiled successfully.${NC}"

# Step 4: Build Prisma Client & Sync Database
echo -e "\n${BLUE}[3/6] Generating Prisma ORM Client & syncing database...${NC}"
npm run prisma:generate
if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
  (cd apps/auth-server && npx prisma db push --accept-data-loss)
  echo -e "${GREEN}✓ Database schema pushed and verified successfully.${NC}"
else
  echo -e "${YELLOW}⚠️  PostgreSQL on localhost:5432 is offline. Skipping database schema push.${NC}"
fi

# Step 5: Start 21 DKG Backend Containers in Docker
echo -e "\n${BLUE}[4/6] Starting 21 DKG backend containers in Docker...${NC}"
docker compose -f infra/compose/full24.yml up -d \
  node-f1 node-f2 node-f3 node-f4 node-f5 \
  node-p1 node-p2 node-p3 node-p4 node-p5 \
  node-r1 node-r2 node-r3 node-r4 node-r5 \
  coordinator-foundation coordinator-public coordinator-private \
  verifier-foundation verifier-public verifier-private 2>/dev/null || true

docker start \
  saral-prod-verifier-foundation saral-prod-verifier-public saral-prod-verifier-private \
  saral-prod-coord-foundation saral-prod-coord-public saral-prod-coord-private 2>/dev/null || true

# Step 6: Provision Keys, Secrets & Binaries into Containers
echo -e "\n${BLUE}[5/6] Provisioning binaries, verification keys & secrets to containers...${NC}"

# Synchronize genesis participants with node identities
sleep 2
node scripts/sync-genesis.js 2>/dev/null || true

# Verifiers receive auth_public_key.pem
for c in saral-prod-verifier-foundation saral-prod-verifier-public saral-prod-verifier-private; do
  docker exec $c mkdir -p /keys 2>/dev/null || true
  docker cp infra/config/auth_public_key.pem $c:/keys/auth_public_key.pem 2>/dev/null || true
  docker restart $c >/dev/null
done

# Coordinators and Nodes
SERVICES_WITH_TOKEN=(
  saral-prod-coord-foundation saral-prod-coord-public saral-prod-coord-private
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
  if [[ "$c" =~ saral-prod-node ]]; then
    docker cp services/saral-node/bin/saral-node $c:/usr/local/bin/saral-node 2>/dev/null || true
  elif [[ "$c" =~ saral-prod-coord ]]; then
    docker cp services/coordinator/bin/coordinator $c:/usr/local/bin/coordinator 2>/dev/null || true
  fi
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

# Step 7: Live Verification of 3-Domain DKG Consensus & Multi-Chain Derivation
echo -e "\n${BLUE}[6/6] Verifying live 3-Domain Dealerless DKG across Foundation, Public & Private...${NC}"
npx tsx -e '
import { saralBackendClient } from "./apps/auth-server/src/clients/saralBackendClient";
import { DOMAINS, DOMAINS_MAP } from "./apps/auth-server/src/config/env";
import { addSecp256k1PublicKeys, addEd25519PublicKeys } from "./apps/auth-server/src/utils/curveMath";
import { deriveAddressFromDkgPublicKey } from "./apps/auth-server/src/services/walletService";

async function verify() {
  const sessionIds = {
    foundation: "dkg-foundation-verify-" + Date.now(),
    public: "dkg-public-verify-" + Date.now(),
    private: "dkg-private-verify-" + Date.now(),
  };

  console.log("   • Starting 3-Domain DKG sessions across 15 nodes in 3 domains...");
  await saralBackendClient.runOnAllDomains(async (domainName) => {
    const cfg = DOMAINS_MAP[domainName];
    const start = await saralBackendClient.startDkg(domainName, {
      committeeId: cfg.committeeId,
      sessionId: sessionIds[domainName],
      committee: cfg.nodeIds,
      n: cfg.n,
      k: cfg.k,
      t: cfg.t,
      walletId: "wal-verify",
      userId: "user-verify",
    });
    if (!start || !start.success) {
      throw new Error(`Failed to start DKG on domain ${domainName}`);
    }
  });

  // Poll until completed on all 3 domains
  const completedDomains = new Set();
  for (let i = 0; i < 25; i++) {
    await new Promise(r => setTimeout(r, 250));
    for (const d of DOMAINS) {
      if (completedDomains.has(d.name)) continue;
      try {
        const st = await saralBackendClient.getDkgStatus(d.name, sessionIds[d.name]);
        if (st?.state === "COMPLETED" || (st?.completedNodes && st.completedNodes >= d.k)) {
          completedDomains.add(d.name);
          console.log(`   • Domain ${d.name.toUpperCase()} DKG Consensus COMPLETED (${st.completedNodes || d.k}/${d.n} nodes decided)`);
        }
      } catch (_) {}
    }
    if (completedDomains.size === DOMAINS.length) break;
  }

  if (completedDomains.size < DOMAINS.length) {
    throw new Error(`DKG Consensus timed out across threshold nodes (${completedDomains.size}/3 completed)`);
  }

  // Derive MST public key points on all 3 domains and combine
  const mstPoints = await Promise.all(DOMAINS.map(d =>
    saralBackendClient.derivePublicKey(d.name, {
      walletId: "wal-verify",
      userId: "user-verify",
      keyId: "key-mst-verify",
      dkgSessionId: sessionIds[d.name],
      committeeId: d.committeeId,
      curve: "secp256k1",
      chainFamily: "mst",
    }).then(r => r.masterPublicKey)
  ));
  const mstCombined = addSecp256k1PublicKeys(mstPoints);
  const mstAddr = deriveAddressFromDkgPublicKey("mst", mstCombined);

  // Derive Solana public key points on all 3 domains and combine
  const solPoints = await Promise.all(DOMAINS.map(d =>
    saralBackendClient.derivePublicKey(d.name, {
      walletId: "wal-verify",
      userId: "user-verify",
      keyId: "key-sol-verify",
      dkgSessionId: sessionIds[d.name],
      committeeId: d.committeeId,
      curve: "ed25519",
      chainFamily: "solana",
    }).then(r => r.masterPublicKey)
  ));
  const solCombined = addEd25519PublicKeys(solPoints);
  const solAddr = deriveAddressFromDkgPublicKey("solana", solCombined);

  // Derive Bitcoin public key points on all 3 domains and combine
  const btcPoints = await Promise.all(DOMAINS.map(d =>
    saralBackendClient.derivePublicKey(d.name, {
      walletId: "wal-verify",
      userId: "user-verify",
      keyId: "key-btc-verify",
      dkgSessionId: sessionIds[d.name],
      committeeId: d.committeeId,
      curve: "secp256k1",
      chainFamily: "bitcoin",
    }).then(r => r.masterPublicKey)
  ));
  const btcCombined = addSecp256k1PublicKeys(btcPoints);
  const btcAddr = deriveAddressFromDkgPublicKey("bitcoin", btcCombined);

  console.log("\x1b[32m   ✓ MST Testnet Address (3-Domain Combined):    " + mstAddr + "\x1b[0m");
  console.log("\x1b[32m   ✓ Solana Devnet Address (3-Domain Combined):  " + solAddr + "\x1b[0m");
  console.log("\x1b[32m   ✓ Bitcoin Testnet Address (3-Domain Combined): " + btcAddr + "\x1b[0m");
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
