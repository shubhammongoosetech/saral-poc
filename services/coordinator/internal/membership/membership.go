package membership

import (
	"fmt"
	"strings"
	"sync"
)

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
