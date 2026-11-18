package membership

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

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

type DomainType string

const (
	DomainFoundation DomainType = "FOUNDATION"
	DomainPublic     DomainType = "PUBLIC"
	DomainPrivate    DomainType = "PRIVATE"
)

type NodeInfo struct {
	NodeID    string     `json:"nodeId"`
	NodeIndex int        `json:"nodeIndex"`
	Domain    DomainType `json:"domain"`
	Endpoint  string     `json:"endpoint"`
}

type NodeRegistry struct {
	domain DomainType
	nodes  map[string]NodeInfo
	mu     sync.RWMutex
}

func NewNodeRegistry(domain DomainType, totalNodes int, basePort int, host string) *NodeRegistry {
	reg := &NodeRegistry{
		domain: domain,
		nodes:  make(map[string]NodeInfo),
	}

	domLower := strings.ToLower(string(domain))
	for i := 1; i <= totalNodes; i++ {
		nodeID := fmt.Sprintf("saral-%s-%d", domLower, i)
		port := basePort + i
		endpoint := fmt.Sprintf("http://%s:%d", host, port)

		reg.nodes[nodeID] = NodeInfo{
			NodeID:    nodeID,
			NodeIndex: i,
			Domain:    domain,
			Endpoint:  endpoint,
		}
	}
	return reg
}

func NewNodeRegistryFromEndpoints(domain DomainType, endpoints []string) *NodeRegistry {
	reg := &NodeRegistry{
		domain: domain,
		nodes:  make(map[string]NodeInfo),
	}

	domLower := strings.ToLower(string(domain))
	for i, ep := range endpoints {
		clean := strings.TrimSpace(ep)
		if clean == "" {
			continue
		}
		index := i + 1
		nodeID := fmt.Sprintf("saral-%s-%d", domLower, index)
		reg.nodes[nodeID] = NodeInfo{
			NodeID:    nodeID,
			NodeIndex: index,
			Domain:    domain,
			Endpoint:  clean,
		}
	}
	return reg
}

func (r *NodeRegistry) GetAllNodes() []NodeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]NodeInfo, 0, len(r.nodes))
	for _, n := range r.nodes {
		out = append(out, n)
	}
	return out
}

func (r *NodeRegistry) GetNode(nodeID string) (NodeInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, exists := r.nodes[nodeID]
	return n, exists
}
