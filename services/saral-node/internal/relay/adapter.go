package relay

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// NodeRelayAdapter implements avss.RelaySender over the authenticated, destination-encrypted RelayRouter
type NodeRelayAdapter struct {
	router *RelayRouter
}

// NewNodeRelayAdapter wraps a RelayRouter as an avss.RelaySender
func NewNodeRelayAdapter(router *RelayRouter) *NodeRelayAdapter {
	return &NodeRelayAdapter{router: router}
}

// SendToNode sends a message of type msgType with raw JSON/byte payload to targetNode
func (a *NodeRelayAdapter) SendToNode(targetNode, targetDomain, msgType string, payload []byte) error {
	var mapPayload map[string]interface{}
	if err := json.Unmarshal(payload, &mapPayload); err != nil {
		mapPayload = map[string]interface{}{"raw": string(payload)}
	}

	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	msgID := fmt.Sprintf("avss-%s-%s", msgType, hex.EncodeToString(randBytes))

	req := RelaySendRequest{
		MessageID:    msgID,
		TargetNode:   targetNode,
		TargetDomain: targetDomain,
		Type:         msgType,
		Payload:      mapPayload,
		TimeoutMs:    15000,
	}

	_, err := a.router.Send(req)
	return err
}
