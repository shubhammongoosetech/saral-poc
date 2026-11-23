package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/discovery"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/health"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/relay"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/rpc"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/tlsutil"
)

func main() {
	domainFlag := flag.String("domain", getEnv("DOMAIN", "FOUNDATION"), "Domain: FOUNDATION | PUBLIC | PRIVATE")
	portFlag := flag.Int("port", getEnvInt("PORT", getEnvInt("RPC_PORT", 9001)), "JSON-RPC Port")
	verifierFlag := flag.String("verifier", getEnv("VERIFIER_URL", "http://localhost:9101"), "Verifier URL")
	nodesFlag := flag.Int("nodes", getEnvInt("TOTAL_NODES", 5), "Total enrolled nodes in domain")
	basePortFlag := flag.Int("base-node-port", getEnvInt("BASE_NODE_PORT", 19100), "Base port for domain nodes")
	nodeHostFlag := flag.String("node-host", getEnv("NODE_HOST", "localhost"), "Host for domain nodes")
	nodeAddrsFlag := flag.String("node-addrs", getEnv("NODE_ADDRS", ""), "Comma-separated list of explicit node endpoints")
	peersFlag := flag.String("peers", getEnv("PEER_COORDINATORS", ""), "Comma-separated peer coordinator endpoints")
	mtlsPortFlag := flag.Int("mtls-port", getEnvInt("MTLS_PORT", 9443), "Port for TLS 1.3 mTLS server (0 to disable)")
	tlsDirFlag := flag.String("tls-dir", getEnv("TLS_DIR", "/etc/saral/tls"), "Directory for TLS certs")
	storageDirFlag := flag.String("storage-dir", getEnv("STORAGE_DIR", ""), "Directory for persistent DKG public sessions")
	flag.Parse()

	domainStr := strings.ToUpper(*domainFlag)
	domain := membership.DomainType(domainStr)
	log.Printf("[SARAL Coordinator - %s] Initializing on port %d...", domain, *portFlag)

	// Validate Kate-Huang-Goldberg HybridVSS parameters: n >= 3t + 2f + 1
	nodesCount := getEnvInt(fmt.Sprintf("SARAL_%s_NODES", domainStr), *nodesFlag)
	tVal := getEnvInt(fmt.Sprintf("SARAL_%s_FAULTS_T", domainStr), getEnvInt("SARAL_FAULTS_T", 1))
	fVal := getEnvInt(fmt.Sprintf("SARAL_%s_CRASH_F", domainStr), getEnvInt("SARAL_CRASH_F", 0))
	if err := rpc.ValidateHybridVSSParameters(nodesCount, tVal, fVal); err != nil {
		log.Fatalf("[SARAL Coordinator - %s] Fatal: %v", domain, err)
	}

	// 1. Setup Node Registry
	var registry *membership.NodeRegistry
	if *nodeAddrsFlag != "" {
		endpoints := strings.Split(*nodeAddrsFlag, ",")
		registry = membership.NewNodeRegistryFromEndpoints(domain, endpoints)
	} else {
		registry = membership.NewNodeRegistry(domain, *nodesFlag, *basePortFlag, *nodeHostFlag)
	}

	// 2. Parse Peer Coordinators
	var peers []string
	if *peersFlag != "" {
		for _, p := range strings.Split(*peersFlag, ",") {
			if clean := strings.TrimSpace(p); clean != "" {
				peers = append(peers, clean)
			}
		}
	}

	// 3. Initialize Discovery Monitor
	monitor := discovery.NewMonitor(registry, peers)
	monitor.Start()
	defer monitor.Stop()

	// 4. Initialize Verifier Client
	verifierClient := relay.NewVerifierClient(*verifierFlag)
	log.Printf("[SARAL Coordinator - %s] Verifier attached at %s", domain, *verifierFlag)

	// 5. Initialize Relay Coordinator
	relayCoord := relay.NewRelayCoordinator(domain, registry, monitor, peers)

	// 6. Mount JSON-RPC and Health endpoints
	rpcServer := rpc.NewServer(domain, registry, monitor, verifierClient, peers, relayCoord)
	if *storageDirFlag != "" {
		rpcServer.SetStorageDir(*storageDirFlag)
	}
	http.Handle("/", rpcServer)
	http.Handle("/rpc", rpcServer)

	http.HandleFunc("/health", health.NewHandler(string(domain), func() int {
		return len(registry.GetAllNodes())
	}, func() int {
		return len(peers)
	}))

	coordID := fmt.Sprintf("saral-coord-%s", strings.ToLower(string(domain)))
	http.HandleFunc("/tls/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mtlsEnabled":   *mtlsPortFlag > 0,
			"tlsVersion":    "TLS 1.3",
			"coordinatorId": coordID,
			"domain":        string(domain),
			"mtlsPort":      *mtlsPortFlag,
			"mutualAuth":    "RequireAndVerifyClientCert",
			"timestamp":     time.Now().UTC().Format(time.RFC3339),
		})
	})

	// 7. Setup TLS 1.3 / mTLS Server & Client
	mtlsPort := *mtlsPortFlag
	if mtlsPort > 0 {
		hosts := []string{
			"localhost",
			"127.0.0.1",
			coordID,
			fmt.Sprintf("coordinator-%s", strings.ToLower(string(domain))),
			fmt.Sprintf("saral-coord-%s", strings.ToLower(string(domain))),
		}
		certPEM, keyPEM, caCertPEM, err := tlsutil.EnsureCertificates(*tlsDirFlag, coordID, hosts)
		if err != nil {
			log.Printf("[SARAL Coordinator - %s] Warning: Failed to provision mTLS certificates: %v", domain, err)
		} else {
			mtlsAddr := fmt.Sprintf(":%d", mtlsPort)
			_, _, err := tlsutil.SetupMTLSServer(mtlsAddr, nil, certPEM, keyPEM, caCertPEM)
			if err != nil {
				log.Printf("[SARAL Coordinator - %s] Warning: Failed to start mTLS server on %s: %v", domain, mtlsAddr, err)
			} else {
				log.Printf("[SARAL Coordinator - %s] mTLS (TLS 1.3 mutual auth) actively listening on %s (Identity: %s)", domain, mtlsAddr, coordID)
				if client, err := tlsutil.NewClient(caCertPEM, certPEM, keyPEM, 12*time.Second); err == nil {
					relayCoord.SetMTLSClient(client)
					monitor.SetMTLSClient(client)
				}
			}
		}
	}

	addr := fmt.Sprintf(":%d", *portFlag)
	log.Printf("[SARAL Coordinator - %s] JSON-RPC listening at http://localhost%s (Managing %d nodes, %d peer coordinators)",
		domain, addr, len(registry.GetAllNodes()), len(peers))

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Coordinator fatal server error: %v", err)
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
