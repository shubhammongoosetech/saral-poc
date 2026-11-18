package proactive

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

// Manager orchestrates epoch management and proactive share refresh for a node
type Manager struct {
	NodeID     string
	Domain     string
	ShareStore *vault.ShareStore
	AVSSEngine *avss.Engine
	Relay      avss.RelaySender

	ActiveCommitteeID string
	ActiveEpoch       uint64
	State             EpochState
	CurrentSession    *RefreshSession

	mu sync.RWMutex
}

// NewManager creates a new proactive epoch manager
func NewManager(
	nodeID, domain string,
	shareStore *vault.ShareStore,
	avssEngine *avss.Engine,
	relay avss.RelaySender,
) *Manager {
	return &Manager{
		NodeID:      nodeID,
		Domain:      domain,
		ShareStore:  shareStore,
		AVSSEngine:  avssEngine,
		Relay:       relay,
		ActiveEpoch: 1,
		State:       EpochStateActive,
	}
}

// GetStatus returns the current node proactive state
func (m *Manager) GetStatus() NodeProactiveState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	refState := RefreshStateIdle
	if m.CurrentSession != nil {
		refState = m.CurrentSession.State
	}

	return NodeProactiveState{
		CommitteeID:       m.ActiveCommitteeID,
		EpochNumber:       m.ActiveEpoch,
		EpochState:        m.State,
		ShareVersion:      m.ActiveEpoch,
		CommitmentVersion: m.ActiveEpoch,
		RefreshState:      refState,
	}
}

// RequestProactiveRefresh initiates an epoch refresh across the committee
func (m *Manager) RequestProactiveRefresh(
	committeeID string,
	committee []string,
	k, t int,
	peerCommitments map[string]*cryptography.CurvePoint,
	masterCommitment *cryptography.CurvePoint,
) (*RefreshSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.State == EpochStateRefreshing {
		return nil, errors.New("proactive refresh already in progress")
	}

	selfIndex := avss.NodeIndexInCommittee(committee, m.NodeID)
	if selfIndex == -1 {
		return nil, fmt.Errorf("node %s not in committee", m.NodeID)
	}

	// Load active share from vault
	meta, oldShare, oldBlindShare, err := m.ShareStore.LoadShare(committeeID, m.ActiveEpoch, m.ActiveEpoch)
	if err != nil {
		return nil, fmt.Errorf("failed to load current share from vault: %w", err)
	}
	_ = meta

	rs, err := NewRefreshSession(
		committeeID, m.ActiveEpoch, m.NodeID, selfIndex, committee,
		k, t, oldShare, oldBlindShare, peerCommitments, masterCommitment,
	)
	if err != nil {
		return nil, err
	}

	m.ActiveCommitteeID = committeeID
	m.CurrentSession = rs
	m.State = EpochStateRefreshing

	// 1. Share current share via AVSS subprotocol
	go m.executeSubprotocolSharing(rs)

	// 2. Broadcast EpochStartMessage to peers
	startMsg := EpochStartMessage{
		CommitteeID: committeeID,
		NewEpoch:    m.ActiveEpoch + 1,
		InitiatorID: m.NodeID,
		Timestamp:   time.Now().UnixMilli(),
	}
	m.broadcastProactive(committee, MessageTypeEpochStart, startMsg)

	return rs, nil
}

func (m *Manager) executeSubprotocolSharing(rs *RefreshSession) {
	// Subprotocol session ID: "refresh-epoch-<newEpoch>-dealer-<selfID>"
	subSessionID := fmt.Sprintf("refresh-epoch-%d-dealer-%s", rs.NewEpoch, m.NodeID)

	_, err := m.AVSSEngine.StartDealerSharing(
		subSessionID, rs.CommitteeID, rs.Committee, rs.K,
		rs.OldShare, rs.OldBlindShare,
	)
	if err != nil {
		log.Printf("[Proactive Manager - %s] Failed to start subprotocol sharing: %v", m.NodeID, err)
		rs.mu.Lock()
		rs.State = RefreshStateFailed
		rs.Error = err.Error()
		rs.mu.Unlock()
	}
}

// HandleEpochStart handles an incoming PROACTIVE_EPOCH_START
func (m *Manager) HandleEpochStart(msg *EpochStartMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if msg.NewEpoch <= m.ActiveEpoch {
		// Reject stale epoch start
		return fmt.Errorf("rejected stale epoch start: newEpoch %d <= activeEpoch %d", msg.NewEpoch, m.ActiveEpoch)
	}

	log.Printf("[Proactive Manager - %s] Received EPOCH_START for epoch %d from %s",
		m.NodeID, msg.NewEpoch, msg.InitiatorID)
	return nil
}

// HandleAgreementPropose processes an incoming proposal for completed sharings
func (m *Manager) HandleAgreementPropose(msg *AgreementProposeMessage) error {
	m.mu.Lock()
	rs := m.CurrentSession
	m.mu.Unlock()

	if rs == nil {
		return errors.New("no active refresh session for agreement proposal")
	}

	echo, err := rs.Agreement.ProcessProposal(msg)
	if err != nil {
		return err
	}

	if echo != nil {
		m.broadcastProactive(rs.Committee, MessageTypeAgreementEcho, echo)
	}
	return nil
}

// HandleAgreementEcho processes an incoming proposal validation echo
func (m *Manager) HandleAgreementEcho(echo *AgreementEchoMessage) error {
	m.mu.Lock()
	rs := m.CurrentSession
	m.mu.Unlock()

	if rs == nil {
		return errors.New("no active refresh session for agreement echo")
	}

	ready, err := rs.Agreement.ProcessEcho(echo)
	if err != nil {
		return err
	}

	if ready != nil {
		m.broadcastProactive(rs.Committee, MessageTypeAgreementReady, ready)
	}
	return nil
}

// HandleAgreementReady processes an incoming agreement ready message
func (m *Manager) HandleAgreementReady(ready *AgreementReadyMessage) error {
	m.mu.Lock()
	rs := m.CurrentSession
	m.mu.Unlock()

	if rs == nil {
		return errors.New("no active refresh session for agreement ready")
	}

	decidedSet, decided, readyToSend, err := rs.Agreement.ProcessReady(ready)
	if err != nil {
		return err
	}

	if readyToSend != nil {
		m.broadcastProactive(rs.Committee, MessageTypeAgreementReady, readyToSend)
	}

	if decided {
		log.Printf("[Proactive Manager - %s] AGREEMENT DECIDED on candidate set %v", m.NodeID, decidedSet)
		// Compute new refreshed share
		if err := rs.ComputeNewShare(decidedSet, m.ShareStore); err != nil {
			log.Printf("[Proactive Manager - %s] Failed computing new share: %v", m.NodeID, err)
			return err
		}

		m.mu.Lock()
		m.ActiveEpoch = rs.NewEpoch
		m.State = EpochStateActive
		m.mu.Unlock()

		log.Printf("[Proactive Manager - %s] PROACTIVE REFRESH SUCCESSFUL! Advanced to epoch %d",
			m.NodeID, rs.NewEpoch)
	}
	return nil
}

func (m *Manager) broadcastProactive(committee []string, msgType string, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	for _, target := range committee {
		if target == m.NodeID {
			continue
		}
		if m.Relay != nil {
			go func(t string, d []byte) {
				_ = m.Relay.SendToNode(t, "", msgType, d)
			}(target, data)
		}
	}
}

