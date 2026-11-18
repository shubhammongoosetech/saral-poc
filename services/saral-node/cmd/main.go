package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/health"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/membership"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/p2p"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/relay"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/rpc"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/tlsutil"
	"github.com/saral-protocol/saral-poc/services/saral-node/proactive"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
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
	mtlsPortFlag := flag.Int("mtls-port", getEnvInt("MTLS_PORT", 8443), "Port for TLS 1.3 mTLS server (0 to disable)")
	tlsDirFlag := flag.String("tls-dir", getEnv("TLS_DIR", "/etc/saral/tls"), "Directory for TLS certs")
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

	// 4b. Initialize AVSS & Proactive Cryptosystems Engines
	privBytes, _ := hex.DecodeString(idMgr.Identity.PrivateKey)
	if len(privBytes) == 0 {
		privBytes = []byte(idMgr.Identity.PrivateKey)
	}
	shareStore, err := vault.NewShareStore(*vaultDirFlag, privBytes)
	if err != nil {
		log.Printf("[SARAL Node - %s] Warning: Failed to initialize share vault: %v", domain, err)
	}
	relayAdapter := relay.NewNodeRelayAdapter(relayRouter)
	avssEngine := avss.NewEngine(idMgr.Identity.NodeID, domain, *vaultDirFlag, shareStore, relayAdapter)
	proactiveMgr := proactive.NewManager(idMgr.Identity.NodeID, domain, shareStore, avssEngine, relayAdapter)

	// Register AVSS and Proactive relay message handlers
	relayRouter.RegisterMessageHandler(avss.MessageTypeSend, func(msg *relay.RelayMessage) error {
		rawBytes, err := json.Marshal(msg.Payload)
		if err != nil {
			return err
		}
		var sendMsg avss.SendMessage
		if err := json.Unmarshal(rawBytes, &sendMsg); err != nil {
			return err
		}
		return avssEngine.HandleSendMessage(&sendMsg)
	})

	relayRouter.RegisterMessageHandler(avss.MessageTypeEcho, func(msg *relay.RelayMessage) error {
		rawBytes, err := json.Marshal(msg.Payload)
		if err != nil {
			return err
		}
		var echoMsg avss.EchoMessage
		if err := json.Unmarshal(rawBytes, &echoMsg); err != nil {
			return err
		}
		return avssEngine.HandleEchoMessage(&echoMsg)
	})

	relayRouter.RegisterMessageHandler(avss.MessageTypeReady, func(msg *relay.RelayMessage) error {
		rawBytes, err := json.Marshal(msg.Payload)
		if err != nil {
			return err
		}
		var readyMsg avss.ReadyMessage
		if err := json.Unmarshal(rawBytes, &readyMsg); err != nil {
			return err
		}
		return avssEngine.HandleReadyMessage(&readyMsg)
	})

	relayRouter.RegisterMessageHandler(proactive.MessageTypeEpochStart, func(msg *relay.RelayMessage) error {
		rawBytes, err := json.Marshal(msg.Payload)
		if err != nil {
			return err
		}
		var startMsg proactive.EpochStartMessage
		if err := json.Unmarshal(rawBytes, &startMsg); err != nil {
			return err
		}
		return proactiveMgr.HandleEpochStart(&startMsg)
	})

	relayRouter.RegisterMessageHandler(proactive.MessageTypeAgreementPropose, func(msg *relay.RelayMessage) error {
		rawBytes, err := json.Marshal(msg.Payload)
		if err != nil {
			return err
		}
		var propMsg proactive.AgreementProposeMessage
		if err := json.Unmarshal(rawBytes, &propMsg); err != nil {
			return err
		}
		return proactiveMgr.HandleAgreementPropose(&propMsg)
	})

	relayRouter.RegisterMessageHandler(proactive.MessageTypeAgreementEcho, func(msg *relay.RelayMessage) error {
		rawBytes, err := json.Marshal(msg.Payload)
		if err != nil {
			return err
		}
		var echoMsg proactive.AgreementEchoMessage
		if err := json.Unmarshal(rawBytes, &echoMsg); err != nil {
			return err
		}
		return proactiveMgr.HandleAgreementEcho(&echoMsg)
	})

	relayRouter.RegisterMessageHandler(proactive.MessageTypeAgreementReady, func(msg *relay.RelayMessage) error {
		rawBytes, err := json.Marshal(msg.Payload)
		if err != nil {
			return err
		}
		var readyMsg proactive.AgreementReadyMessage
		if err := json.Unmarshal(rawBytes, &readyMsg); err != nil {
			return err
		}
		return proactiveMgr.HandleAgreementReady(&readyMsg)
	})

	// 5. Setup HTTP Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/node/health", health.NewHandler(idMgr.Identity.NodeID, domain, startTime))
	mux.HandleFunc("/health", health.NewHandler(idMgr.Identity.NodeID, domain, startTime))
	mux.HandleFunc("/tls/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mtlsEnabled": *mtlsPortFlag > 0,
			"tlsVersion":  "TLS 1.3",
			"nodeId":      defaultID,
			"domain":      domain,
			"mtlsPort":    *mtlsPortFlag,
			"mutualAuth":  "RequireAndVerifyClientCert",
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/node/tls/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mtlsEnabled": *mtlsPortFlag > 0,
			"tlsVersion":  "TLS 1.3",
			"nodeId":      defaultID,
			"domain":      domain,
			"mtlsPort":    *mtlsPortFlag,
			"mutualAuth":  "RequireAndVerifyClientCert",
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		})
	})

	rpc.RegisterRoutes(mux, idMgr, domain, *nodeIndexFlag, p2pMgr, relayRouter, startTime)
	rpc.RegisterAVSSRoutes(mux, avssEngine, proactiveMgr)

	// 6. Setup TLS 1.3 / mTLS Server & Client
	mtlsPort := *mtlsPortFlag
	if mtlsPort > 0 {
		hosts := []string{
			"localhost",
			"127.0.0.1",
			defaultID,
			fmt.Sprintf("node-%s%d", strings.ToLower(domain[:1]), *nodeIndexFlag),
			fmt.Sprintf("saral-node-%s%d", strings.ToLower(domain[:1]), *nodeIndexFlag),
		}
		certPEM, keyPEM, caCertPEM, err := tlsutil.EnsureCertificates(*tlsDirFlag, defaultID, hosts)
		if err != nil {
			log.Printf("[SARAL Node - %s] Warning: Failed to provision mTLS certificates: %v", domain, err)
		} else {
			mtlsAddr := fmt.Sprintf(":%d", mtlsPort)
			_, _, err := tlsutil.SetupMTLSServer(mtlsAddr, mux, certPEM, keyPEM, caCertPEM)
			if err != nil {
				log.Printf("[SARAL Node - %s] Warning: Failed to start mTLS server on %s: %v", domain, mtlsAddr, err)
			} else {
				log.Printf("[SARAL Node - %s] mTLS (TLS 1.3 mutual auth) actively listening on %s (Identity: %s)", domain, mtlsAddr, defaultID)
				if client, err := tlsutil.NewClient(caCertPEM, certPEM, keyPEM, 5*time.Second); err == nil {
					p2pMgr.SetMTLSClient(client)
					relayRouter.SetMTLSClient(client)
				}
			}
		}
	}

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
