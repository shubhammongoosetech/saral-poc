package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/health"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/membership"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/p2p"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/relay"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/rpc"
)

func main() {
	nodeIDFlag := flag.String("node-id", getEnv("NODE_ID", ""), "Node identifier")
	domainFlag := flag.String("domain", getEnv("DOMAIN", "FOUNDATION"), "Domain: FOUNDATION | PUBLIC | PRIVATE")
	nodeIndexFlag := flag.Int("node-index", getEnvInt("NODE_INDEX", 1), "Node index in domain")
	portFlag := flag.Int("port", getEnvInt("PORT", 8001), "HTTP Port for Node RPC & health")
	p2pPortFlag := flag.Int("p2p-port", getEnvInt("P2P_PORT", 28001), "P2P port for peer communications")
	peersFlag := flag.String("peers", getEnv("PEER_NODES", ""), "Comma-separated peer endpoints")
	vaultDirFlag := flag.String("vault-dir", getEnv("VAULT_DIR", ""), "Vault directory for persistent identity")
	coordinatorURLFlag := flag.String("coordinator-url", getEnv("COORDINATOR_URL", ""), "Domain Coordinator URL")
	flag.Parse()

	domain := strings.ToUpper(*domainFlag)
	defaultID := *nodeIDFlag
	if defaultID == "" {
		defaultID = fmt.Sprintf("saral-%s-%d", strings.ToLower(domain), *nodeIndexFlag)
	}

	startTime := time.Now()

	// 1. Load or Generate Persistent Ed25519 Identity
	idMgr, err := identity.LoadOrGenerateIdentity(*vaultDirFlag, defaultID, domain, *nodeIndexFlag)
	if err != nil {
		log.Fatalf("[SARAL Node] Fatal error loading identity: %v", err)
	}

	log.Printf("[SARAL Node - %s] Identity: %s (Public Key: %s..., P2P Port: %d)",
		domain, idMgr.Identity.NodeID, idMgr.Identity.PublicKeyHex[:16], *p2pPortFlag)

	// 2. Parse peer endpoints
	var peers []string
	if *peersFlag != "" {
		peers = strings.Split(*peersFlag, ",")
	}
	selfEndpoint := fmt.Sprintf("http://localhost:%d", *portFlag)
	cleanedPeers := membership.CleanPeers(peers, selfEndpoint)

	// 3. Initialize P2P Mesh Manager
	p2pMgr := p2p.NewP2PManager(idMgr, domain, cleanedPeers)
	p2pMgr.Start()
	defer p2pMgr.Stop()

	// 4. Initialize Relay Router
	coordURL := *coordinatorURLFlag
	if coordURL == "" {
		domainOffset := 0
		switch domain {
		case "PUBLIC":
			domainOffset = 1
		case "PRIVATE":
			domainOffset = 2
		}
		coordURL = fmt.Sprintf("http://coordinator-%s:%d", strings.ToLower(domain), 9001+domainOffset)
	}

	relayRouter := relay.NewRelayRouter(idMgr, domain, p2pMgr, coordURL, *vaultDirFlag)
	defer relayRouter.Stop()

	// 5. Setup HTTP Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/node/health", health.NewHandler(idMgr.Identity.NodeID, domain, startTime))
	mux.HandleFunc("/health", health.NewHandler(idMgr.Identity.NodeID, domain, startTime))

	rpc.RegisterRoutes(mux, idMgr, domain, *nodeIndexFlag, p2pMgr, relayRouter, startTime)

	addr := fmt.Sprintf(":%d", *portFlag)
	log.Printf("[SARAL Node - %s] Listening at http://localhost%s (P2P Mesh with %d configured peers, Coordinator: %s)",
		domain, addr, len(cleanedPeers), *coordinatorURLFlag)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("SARAL Node server fatal error: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		var out int
		if _, err := fmt.Sscanf(v, "%d", &out); err == nil {
			return out
		}
	}
	return defaultVal
}
