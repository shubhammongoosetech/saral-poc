package membership

import (
	"fmt"
	"strconv"
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

type ParticipantEntry struct {
	NodeID       string `json:"nodeId"`
	Domain       string `json:"domain"`
	PublicKeyHex string `json:"publicKeyHex"`
	Endpoint     string `json:"endpoint,omitempty"`
}

// NormalizeNodeID converts user/test aliases into canonical "saral-foundation-1"
func NormalizeNodeID(raw string) (string, string) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "saral-")
	s = strings.TrimPrefix(s, "node-")

	var domain, numStr string
	if strings.HasPrefix(s, "foundation") {
		domain = "FOUNDATION"
		numStr = strings.TrimPrefix(s, "foundation")
	} else if strings.HasPrefix(s, "public") {
		domain = "PUBLIC"
		numStr = strings.TrimPrefix(s, "public")
	} else if strings.HasPrefix(s, "private") {
		domain = "PRIVATE"
		numStr = strings.TrimPrefix(s, "private")
	} else if strings.HasPrefix(s, "f") {
		domain = "FOUNDATION"
		numStr = strings.TrimPrefix(s, "f")
	} else if strings.HasPrefix(s, "p") {
		domain = "PUBLIC"
		numStr = strings.TrimPrefix(s, "p")
	} else if strings.HasPrefix(s, "r") {
		domain = "PRIVATE"
		numStr = strings.TrimPrefix(s, "r")
	}

	numStr = strings.Trim(numStr, "-_")
	num, err := strconv.Atoi(numStr)
	if err == nil && domain != "" {
		return fmt.Sprintf("saral-%s-%d", strings.ToLower(domain), num), domain
	}

	if strings.Contains(s, "foundation") {
		return raw, "FOUNDATION"
	} else if strings.Contains(s, "public") {
		return raw, "PUBLIC"
	} else if strings.Contains(s, "private") {
		return raw, "PRIVATE"
	}
	return raw, "UNKNOWN"
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
