package membership

import (
	"strings"
)

type NodeConfig struct {
	NodeID          string   `json:"nodeId"`
	Domain          string   `json:"domain"`
	NodeIndex       int      `json:"nodeIndex"`
	HTTPPort        int      `json:"httpPort"`
	P2PPort         int      `json:"p2pPort"`
	AdvertisedAddr  string   `json:"advertisedAddr"`
	ConfiguredPeers []string `json:"configuredPeers"`
	VaultDir        string   `json:"vaultDir"`
}

func CleanPeers(peers []string, selfEndpoint string) []string {
	var cleaned []string
	seen := make(map[string]bool)

	for _, p := range peers {
		trim := strings.TrimSpace(p)
		if trim == "" || trim == selfEndpoint || seen[trim] {
			continue
		}
		seen[trim] = true
		cleaned = append(cleaned, trim)
	}
	return cleaned
}
