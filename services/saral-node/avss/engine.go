package avss

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

// RelaySender defines the interface for transmitting protocol messages over the SARAL relay
type RelaySender interface {
	SendToNode(targetNode, targetDomain, msgType string, payload []byte) error
}

// SharingCompletionListener is called whenever an AVSS session successfully completes
type SharingCompletionListener func(sessionID string, sess *Session)

// Engine manages the local node's AVSS protocol sessions, relay routing, and share lifecycle
type Engine struct {
	NodeID       string
	Domain       string
	VaultDir     string
	ShareStore   *vault.ShareStore
	SessionStore *SessionStore
	Relay        RelaySender

	sessions            map[string]*Session
	completionListeners []SharingCompletionListener
	mu                  sync.RWMutex
}

// NewEngine initializes the AVSS protocol engine
func NewEngine(
	nodeID, domain, vaultDir string,
	shareStore *vault.ShareStore,
	relay RelaySender,
) *Engine {
	return &Engine{
		NodeID:       nodeID,
		Domain:       domain,
		VaultDir:     vaultDir,
		ShareStore:   shareStore,
		SessionStore: NewSessionStore(vaultDir),
		Relay:        relay,
		sessions:     make(map[string]*Session),
	}
}

// AddCompletionListener registers a callback invoked when any AVSS session finishes
func (e *Engine) AddCompletionListener(listener SharingCompletionListener) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.completionListeners = append(e.completionListeners, listener)
}

// GetSession returns an active session by ID
func (e *Engine) GetSession(sessionID string) (*Session, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sess, exists := e.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	return sess, nil
}

// CreateSession initializes and registers a new AVSS session
func (e *Engine) CreateSession(
	sessionID, committeeID, dealerID string,
	epoch uint64,
	n, k, t int,
	committee []string,
) (*Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.sessions[sessionID]; exists {
		return e.sessions[sessionID], nil
	}

	selfIndex := NodeIndexInCommittee(committee, e.NodeID)
	if selfIndex == -1 {
		return nil, fmt.Errorf("local node %s is not a member of the cryptographic committee", e.NodeID)
	}

	sess, err := NewSession(sessionID, committeeID, dealerID, e.NodeID, selfIndex, epoch, n, k, t, committee)
	if err != nil {
		return nil, err
	}

	e.sessions[sessionID] = sess
	return sess, nil
}

// StartDealerSharing initiates a new AVSS sharing as the designated dealer
func (e *Engine) StartDealerSharing(
	sessionID, committeeID string,
	committee []string,
	k int,
	explicitSecret *cryptography.FieldElement,
	explicitBlindSecret *cryptography.FieldElement,
) (*DealerPackage, error) {
	n := len(committee)
	t := (n - 1) / 3
	for candT := (n - k) / 2; candT >= 0; candT-- {
		if k > candT && n-2*candT >= k {
			t = candT
			break
		}
	}

	sess, err := e.CreateSession(sessionID, committeeID, e.NodeID, 1, n, k, t, committee)
	if err != nil {
		return nil, fmt.Errorf("failed to create dealer session: %w", err)
	}

	sess.mu.Lock()
	sess.State = StateDealerDistributing
	sess.mu.Unlock()

	pkg, err := GenerateDealerSharing(sessionID, committeeID, e.NodeID, 1, committee, k, explicitSecret, explicitBlindSecret)
	if err != nil {
		sess.mu.Lock()
		sess.State = StateSharingFailed
		sess.Error = err.Error()
		sess.mu.Unlock()
		return nil, err
	}

	// Dispatch private SEND messages to each committee participant via relay
	for targetNode, sendMsg := range pkg.SendMessages {
		payloadBytes, err := json.Marshal(sendMsg)
		if err != nil {
			log.Printf("[AVSS Engine] Error marshaling SEND message for %s: %v", targetNode, err)
			continue
		}

		if targetNode == e.NodeID {
			// Deliver to self directly
			go func(m *SendMessage) {
				_ = e.HandleSendMessage(m)
			}(sendMsg)
		} else if e.Relay != nil {
			go func(target string, data []byte) {
				if err := e.Relay.SendToNode(target, "", MessageTypeSend, data); err != nil {
					log.Printf("[AVSS Engine] Failed to dispatch SEND to %s: %v", target, err)
				}
			}(targetNode, payloadBytes)
		}
	}

	return pkg, nil
}

// HandleSendMessage processes an incoming AVSS_SEND message
func (e *Engine) HandleSendMessage(msg *SendMessage) error {
	sess, err := e.GetSession(msg.SessionID)
	if err != nil {
		// Session not yet created; auto-init from message parameters if recipient is in committee
		// In a standard committee, n = len(msg.Commitments[0]) or known committee
		// If session not found, create it using dealer message data
		k := len(msg.Commitments)
		// Assume dealer sent to known committee or self is recipient
		// Create session with parameters
		committee := []string{e.NodeID} // will be resolved if registered
		n := 15                          // default global POC15 or 5
		t := 4
		if k <= 3 {
			n = 5
			t = 1
		}
		sess, err = e.CreateSession(msg.SessionID, msg.CommitteeID, msg.DealerID, msg.Epoch, n, k, t, committee)
		if err != nil {
			return fmt.Errorf("failed to auto-create session for incoming SEND: %w", err)
		}
	}

	if msg.Curve != "" && sess.Curve == "" {
		sess.Curve = msg.Curve
	}

	echos, err := sess.ProcessSendMessage(msg)
	if err != nil {
		return err
	}

	// Broadcast ECHOs to all peers in the committee
	e.broadcastEchos(echos)
	return nil
}

// HandleEchoMessage processes an incoming AVSS_ECHO message
func (e *Engine) HandleEchoMessage(echo *EchoMessage) error {
	sess, err := e.GetSession(echo.SessionID)
	if err != nil {
		return err
	}

	readys, err := sess.ProcessEchoMessage(echo)
	if err != nil {
		return err
	}

	if len(readys) > 0 {
		e.broadcastReadys(readys)
	}

	sess.mu.RLock()
	isCompleted := (sess.State == StateSharingCompleted)
	sess.mu.RUnlock()
	if isCompleted {
		e.onSharingCompleted(sess)
	}
	return nil
}

// HandleReadyMessage processes an incoming AVSS_READY message
func (e *Engine) HandleReadyMessage(ready *ReadyMessage) error {
	sess, err := e.GetSession(ready.SessionID)
	if err != nil {
		return err
	}

	completed, readysToSend, err := sess.ProcessReadyMessage(ready)
	if err != nil {
		return err
	}

	if len(readysToSend) > 0 {
		e.broadcastReadys(readysToSend)
	}

	if completed {
		e.onSharingCompleted(sess)
	}
	return nil
}

func (e *Engine) broadcastEchos(echos []*EchoMessage) {
	for _, echo := range echos {
		payloadBytes, err := json.Marshal(echo)
		if err != nil {
			continue
		}
		if echo.RecipientID == e.NodeID {
			go func(m *EchoMessage) {
				_ = e.HandleEchoMessage(m)
			}(echo)
		} else if e.Relay != nil {
			go func(target string, data []byte) {
				_ = e.Relay.SendToNode(target, "", MessageTypeEcho, data)
			}(echo.RecipientID, payloadBytes)
		}
	}
}

func (e *Engine) broadcastReadys(readys []*ReadyMessage) {
	for _, ready := range readys {
		payloadBytes, err := json.Marshal(ready)
		if err != nil {
			continue
		}
		if ready.RecipientID == e.NodeID {
			go func(m *ReadyMessage) {
				_ = e.HandleReadyMessage(m)
			}(ready)
		} else if e.Relay != nil {
			go func(target string, data []byte) {
				_ = e.Relay.SendToNode(target, "", MessageTypeReady, data)
			}(ready.RecipientID, payloadBytes)
		}
	}
}

func (e *Engine) onSharingCompleted(sess *Session) {
	log.Printf("[AVSS Engine - %s] SHARING_COMPLETED for session %s (epoch %d, k=%d, t=%d)",
		e.NodeID, sess.SessionID, sess.Epoch, sess.K, sess.T)

	// Persist non-secret session metadata
	if e.SessionStore != nil {
		pubShareHex := ""
		if sess.PublicShareCommitment != nil {
			pubShareHex = sess.PublicShareCommitment.Hex()
		}
		pubSecHex := ""
		if sess.PublicSecretCommitment != nil {
			pubSecHex = sess.PublicSecretCommitment.Hex()
		}
		rec := &SessionRecord{
			SessionID:              sess.SessionID,
			CommitteeID:            sess.CommitteeID,
			DealerID:               sess.DealerID,
			NodeID:                 e.NodeID,
			Epoch:                  sess.Epoch,
			N:                      sess.N,
			K:                      sess.K,
			T:                      sess.T,
			State:                  string(StateSharingCompleted),
			PublicShareCommitment:  pubShareHex,
			PublicSecretCommitment: pubSecHex,
			CreatedAt:              sess.CreatedAt.UnixMilli(),
			UpdatedAt:              time.Now().UnixMilli(),
		}
		_ = e.SessionStore.SaveSession(rec)
	}

	// Persist share in vault with AES-GCM encryption and 0600 permissions
	if e.ShareStore != nil && sess.Share != nil && sess.BlindShare != nil {
		meta := vault.ShareRecordMetadata{
			CommitteeID:            sess.CommitteeID,
			SessionID:              sess.SessionID,
			NodeID:                 e.NodeID,
			NodeIndex:              sess.SelfIndex,
			Epoch:                  sess.Epoch,
			ShareVersion:           1,
			State:                  "ACTIVE",
			PublicShareCommitment:  sess.PublicShareCommitment.Hex(),
			PublicSecretCommitment: sess.PublicSecretCommitment.Hex(),
			CreatedAt:              sess.CreatedAt.UnixMilli(),
			UpdatedAt:              time.Now().UnixMilli(),
		}
		if err := e.ShareStore.SaveShare(meta, sess.Share, sess.BlindShare); err != nil {
			log.Printf("[AVSS Engine - %s] Error persisting share to vault: %v", e.NodeID, err)
		}
	}

	// Notify registered observers (DKG Engine, Proactive Manager)
	e.mu.RLock()
	listeners := make([]SharingCompletionListener, len(e.completionListeners))
	copy(listeners, e.completionListeners)
	e.mu.RUnlock()

	for _, l := range listeners {
		l(sess.SessionID, sess)
	}
}

