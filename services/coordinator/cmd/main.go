package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/discovery"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/health"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/relay"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/rpc"
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
	flag.Parse()

	domain := membership.DomainType(strings.ToUpper(*domainFlag))
	log.Printf("[SARAL Coordinator - %s] Initializing on port %d...", domain, *portFlag)

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
	http.Handle("/", rpcServer)
	http.Handle("/rpc", rpcServer)

	http.HandleFunc("/health", health.NewHandler(string(domain), func() int {
		return len(registry.GetAllNodes())
	}, func() int {
		return len(peers)
	}))

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
