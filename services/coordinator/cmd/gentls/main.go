package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/tlsutil"
)

func main() {
	outDir := "infra/tls"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("failed to create output dir: %v", err)
	}

	caCertPath := filepath.Join(outDir, "ca.crt")
	caKeyPath := filepath.Join(outDir, "ca.key")

	var caCert, caKey []byte

	if _, err := os.Stat(caCertPath); err == nil {
		caCert, _ = os.ReadFile(caCertPath)
		caKey, _ = os.ReadFile(caKeyPath)
		fmt.Printf("Using existing CA at %s\n", caCertPath)
	} else {
		caCert, caKey, err = tlsutil.GenerateCA("SARAL Protocol Cluster Root CA")
		if err != nil {
			log.Fatalf("failed to generate CA: %v", err)
		}
		_ = os.WriteFile(caCertPath, caCert, 0644)
		_ = os.WriteFile(caKeyPath, caKey, 0600)
		fmt.Printf("Generated new Root CA at %s\n", caCertPath)
	}

	type certSpec struct {
		id    string
		hosts []string
	}

	specs := []certSpec{
		// Coordinators
		{id: "saral-coord-foundation", hosts: []string{"localhost", "127.0.0.1", "coordinator-foundation", "saral-coord-foundation"}},
		{id: "saral-coord-public", hosts: []string{"localhost", "127.0.0.1", "coordinator-public", "saral-coord-public"}},
		{id: "saral-coord-private", hosts: []string{"localhost", "127.0.0.1", "coordinator-private", "saral-coord-private"}},
		// Test Client
		{id: "saral-test-client", hosts: []string{"localhost", "127.0.0.1"}},
	}

	// 15 Nodes
	domains := []struct {
		dom   string
		pfx   string
		short string
	}{
		{"foundation", "saral-foundation", "f"},
		{"public", "saral-public", "p"},
		{"private", "saral-private", "r"},
	}

	for _, d := range domains {
		for i := 1; i <= 5; i++ {
			nodeID := fmt.Sprintf("%s-%d", d.pfx, i)
			containerHost := fmt.Sprintf("node-%s%d", d.short, i)
			containerName := fmt.Sprintf("saral-node-%s%d", d.short, i)
			specs = append(specs, certSpec{
				id:    nodeID,
				hosts: []string{"localhost", "127.0.0.1", containerHost, containerName, nodeID},
			})
		}
	}

	for _, spec := range specs {
		certPath := filepath.Join(outDir, spec.id+".crt")
		keyPath := filepath.Join(outDir, spec.id+".key")

		certBytes, keyBytes, err := tlsutil.GenerateCert(caCert, caKey, spec.id, spec.hosts)
		if err != nil {
			log.Fatalf("failed to generate cert for %s: %v", spec.id, err)
		}

		_ = os.WriteFile(certPath, certBytes, 0644)
		_ = os.WriteFile(keyPath, keyBytes, 0600)
		fmt.Printf("  -> Generated certificate for %s (CN=%s, SANs=%v)\n", spec.id, spec.id, spec.hosts)
	}

	fmt.Println("All cluster mTLS certificates successfully generated!")
}
