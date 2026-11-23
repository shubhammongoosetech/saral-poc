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

# Step 1.1: Ensure untracked local .env exists with securely generated secrets (FIX 8c)
if [ ! -f .env ]; then
  echo "Creating .env from .env.example with securely generated random secrets..."
  cp .env.example .env
  JWT_HEX=$(openssl rand -hex 32)
  MFA_HEX=$(openssl rand -hex 32)
  OTP_HEX=$(openssl rand -hex 32)
  TOKEN_HEX=$(openssl rand -hex 32)
  sed -i "s/JWT_SECRET=.*/JWT_SECRET=${JWT_HEX}/" .env
  sed -i "s/MFA_ENCRYPTION_KEY=.*/MFA_ENCRYPTION_KEY=${MFA_HEX}/" .env
  sed -i "s/OTP_PEPPER=.*/OTP_PEPPER=${OTP_HEX}/" .env
  sed -i "s/SARAL_INTERNAL_TOKEN=.*/SARAL_INTERNAL_TOKEN=${TOKEN_HEX}/" .env
fi

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
fi
chmod 600 infra/secrets/internal_token.secret 2>/dev/null || true

# Ensure genesis participants file exists on host before compose mounts it
if [ ! -f infra/config/genesis_participants.json ]; then
  echo "{}" > infra/config/genesis_participants.json
fi
chmod 600 infra/config/genesis_participants.json 2>/dev/null || true
chmod 600 infra/config/auth_public_key.pem 2>/dev/null || true
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
F_NODES=${SARAL_FOUNDATION_NODES:-5}
P_NODES=${SARAL_PUBLIC_NODES:-5}
R_NODES=${SARAL_PRIVATE_NODES:-5}

NODE_SERVICES=()
for ((i=1; i<=F_NODES; i++)); do NODE_SERVICES+=("node-f$i"); done
for ((i=1; i<=P_NODES; i++)); do NODE_SERVICES+=("node-p$i"); done
for ((i=1; i<=R_NODES; i++)); do NODE_SERVICES+=("node-r$i"); done

ALL_SERVICES=(
  verifier-foundation verifier-public verifier-private
  coordinator-foundation coordinator-public coordinator-private
  "${NODE_SERVICES[@]}"
)

docker compose -f infra/compose/full24.yml up -d "${ALL_SERVICES[@]}"

# Step 6: Synchronize Genesis Participants & Deploy Fresh Binaries
echo -e "\n${BLUE}[5/6] Synchronizing node identities & deploying latest binaries...${NC}"

# Synchronize genesis participants with generated node identities from vaults
sleep 2
node scripts/sync-genesis.js 2>/dev/null || true

# Deploy latest compiled binaries to running containers
for c in "${NODE_SERVICES[@]}"; do
  docker cp services/saral-node/bin/saral-node "saral-prod-$c":/usr/local/bin/saral-node 2>/dev/null || true
done
for c in saral-prod-coord-foundation saral-prod-coord-public saral-prod-coord-private; do
  docker cp services/coordinator/bin/coordinator "$c":/usr/local/bin/coordinator 2>/dev/null || true
done
for c in saral-prod-verifier-foundation saral-prod-verifier-public saral-prod-verifier-private; do
  docker cp services/verifier/bin/verifier "$c":/usr/local/bin/verifier 2>/dev/null || true
done

# Restart coordinators and nodes so they pick up synced genesis and latest binary
RESTART_CONTAINERS=(
  saral-prod-coord-foundation saral-prod-coord-public saral-prod-coord-private
)
for c in "${NODE_SERVICES[@]}"; do
  RESTART_CONTAINERS+=("saral-prod-$c")
done

for c in "${RESTART_CONTAINERS[@]}"; do
  docker restart "$c" >/dev/null &
done
wait

echo "Waiting for all 3 coordinators and 15 nodes to become healthy and registered..."
MAX_WAIT=30
START_TIME=$(date +%s)
ALL_REGISTERED=false

while [ $(($(date +%s) - START_TIME)) -lt $MAX_WAIT ]; do
  F_REG=$(curl -s http://localhost:9001/health | grep -o '"enrolledNodes":[0-9]*' | cut -d: -f2 || echo 0)
  P_REG=$(curl -s http://localhost:9002/health | grep -o '"enrolledNodes":[0-9]*' | cut -d: -f2 || echo 0)
  R_REG=$(curl -s http://localhost:9003/health | grep -o '"enrolledNodes":[0-9]*' | cut -d: -f2 || echo 0)

  if [ "${F_REG:-0}" -ge "$F_NODES" ] && [ "${P_REG:-0}" -ge "$P_NODES" ] && [ "${R_REG:-0}" -ge "$R_NODES" ]; then
    ALL_REGISTERED=true
    break
  fi
  sleep 1
done

if [ "$ALL_REGISTERED" = true ]; then
  echo -e "${GREEN}✓ FOUNDATION domain: ${F_REG}/${F_NODES} nodes registered${NC}"
  echo -e "${GREEN}✓ PUBLIC domain:     ${P_REG}/${P_NODES} nodes registered${NC}"
  echo -e "${GREEN}✓ PRIVATE domain:    ${R_REG}/${R_NODES} nodes registered${NC}"
  echo -e "${GREEN}✓ All 21 DKG backend containers are healthy and all 15 nodes registered across 3 domains.${NC}"
else
  echo -e "${RED}⚠️  Warning: Timeout waiting for all nodes to register (Foundation: ${F_REG:-0}/${F_NODES}, Public: ${P_REG:-0}/${P_NODES}, Private: ${R_REG:-0}/${R_NODES})${NC}"
fi

# Step 7: Live Verification of 3-Domain Multi-Curve DKG (6 Sessions: 3 Domains x 2 Curves)
echo -e "\n${BLUE}[6/6] Verifying live 3-Domain Dealerless DKG across Foundation, Public & Private...${NC}"
npx tsx -e '
import { saralBackendClient } from "./apps/auth-server/src/clients/saralBackendClient";
import { DOMAINS, DOMAINS_MAP } from "./apps/auth-server/src/config/env";
import { addSecp256k1PublicKeys, addEd25519PublicKeys } from "./apps/auth-server/src/utils/curveMath";
import { deriveAddressFromDkgPublicKey } from "./apps/auth-server/src/services/walletService";

async function verify() {
  const ts = Date.now();
  const testUserId = `user-verify-${ts}`;
  const testWalletId = `wal-verify-${ts}`;

  const curves = ["secp256k1", "ed25519"] as const;
  const sessionIds: Record<string, { secp256k1: string; ed25519: string }> = {
    foundation: { secp256k1: `dkg-found-secp-${ts}`, ed25519: `dkg-found-ed-${ts}` },
    public: { secp256k1: `dkg-pub-secp-${ts}`, ed25519: `dkg-pub-ed-${ts}` },
    private: { secp256k1: `dkg-priv-secp-${ts}`, ed25519: `dkg-priv-ed-${ts}` },
  };

  console.log("   • Starting 6 DKG sessions across 3 domains x 2 curves (secp256k1 & ed25519)...");

  const startPromises: Promise<any>[] = [];
  for (const d of DOMAINS) {
    const cfg = DOMAINS_MAP[d.name];
    for (const curve of curves) {
      const sessId = sessionIds[d.name][curve];
      const chainFamily = curve === "ed25519" ? "solana" : "mst";
      startPromises.push(
        saralBackendClient.startDkg(d.name, {
          committeeId: cfg.committeeId,
          sessionId: sessId,
          committee: cfg.nodeIds,
          n: cfg.n,
          k: cfg.k,
          t: cfg.t,
          walletId: testWalletId,
          userId: testUserId,
          keyId: `key-${curve}-${d.name}`,
          curve,
          chainFamily,
        })
      );
    }
  }
  await Promise.all(startPromises);

  const totalSessions = 6;
  const completedSessions = new Set<string>();
  const timeoutMs = parseInt(process.env.SARAL_DKG_TIMEOUT_MS || "30000", 10);
  const deadline = Date.now() + timeoutMs;
  const lastStatuses: Record<string, any> = {};

  while (Date.now() < deadline) {
    for (const d of DOMAINS) {
      for (const curve of curves) {
        const sessId = sessionIds[d.name][curve];
        const key = `${d.name}:${curve}`;
        if (completedSessions.has(key)) continue;
        try {
          const st = await saralBackendClient.getDkgStatus(d.name, sessId);
          lastStatuses[key] = st;
          if (st?.state === "COMPLETED" && st?.masterPublicKey && (st.completedNodes || 0) >= d.k) {
            completedSessions.add(key);
            console.log(`   • [${d.name.toUpperCase()}] curve=${curve} DKG COMPLETED (${st.completedNodes || d.k}/${d.n} nodes decided)`);
          }
        } catch (_) {}
      }
    }
    if (completedSessions.size === totalSessions) break;
    await new Promise((r) => setTimeout(r, 400));
  }

  if (completedSessions.size < totalSessions) {
    const failed = [];
    for (const d of DOMAINS) {
      for (const curve of curves) {
        const key = `${d.name}:${curve}`;
        if (!completedSessions.has(key)) {
          failed.push(`${key} (status: ${JSON.stringify(lastStatuses[key] || "no status")})`);
        }
      }
    }
    throw new Error(`DKG Consensus timed out: ${completedSessions.size}/${totalSessions} completed. Incomplete: ${failed.join(", ")}`);
  }

  // Derive MST public key points on all 3 domains (secp256k1) and combine
  const mstPoints = await Promise.all(
    DOMAINS.map((d) =>
      saralBackendClient.derivePublicKey(d.name, {
        walletId: testWalletId,
        userId: testUserId,
        keyId: `key-secp256k1-${d.name}`,
        dkgSessionId: sessionIds[d.name].secp256k1,
        committeeId: d.committeeId,
        curve: "secp256k1",
        chainFamily: "mst",
      }).then((r) => r.masterPublicKey)
    )
  );
  const mstCombined = addSecp256k1PublicKeys(mstPoints);
  const mstAddr = deriveAddressFromDkgPublicKey("mst", mstCombined);

  // Derive Solana public key points on all 3 domains (ed25519) and combine
  const solPoints = await Promise.all(
    DOMAINS.map((d) =>
      saralBackendClient.derivePublicKey(d.name, {
        walletId: testWalletId,
        userId: testUserId,
        keyId: `key-ed25519-${d.name}`,
        dkgSessionId: sessionIds[d.name].ed25519,
        committeeId: d.committeeId,
        curve: "ed25519",
        chainFamily: "solana",
      }).then((r) => r.masterPublicKey)
    )
  );
  const solCombined = addEd25519PublicKeys(solPoints);
  const solAddr = deriveAddressFromDkgPublicKey("solana", solCombined);

  // Derive Bitcoin public key points on all 3 domains (secp256k1) and combine
  const btcPoints = await Promise.all(
    DOMAINS.map((d) =>
      saralBackendClient.derivePublicKey(d.name, {
        walletId: testWalletId,
        userId: testUserId,
        keyId: `key-secp256k1-${d.name}`,
        dkgSessionId: sessionIds[d.name].secp256k1,
        committeeId: d.committeeId,
        curve: "secp256k1",
        chainFamily: "bitcoin",
      }).then((r) => r.masterPublicKey)
    )
  );
  const btcCombined = addSecp256k1PublicKeys(btcPoints);
  const btcAddr = deriveAddressFromDkgPublicKey("bitcoin", btcCombined);

  console.log("\x1b[32m   ✓ MST Testnet Address (3-Domain Combined):    " + mstAddr + "\x1b[0m");
  console.log("\x1b[32m   ✓ Solana Devnet Address (3-Domain Combined):  " + solAddr + "\x1b[0m");
  console.log("\x1b[32m   ✓ Bitcoin Testnet Address (3-Domain Combined): " + btcAddr + "\x1b[0m");
}

verify().catch((e) => {
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
