package proactive

import (
	"errors"
	"log"

	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

var (
	ErrEpochDesynchronized = errors.New("node local epoch is desynchronized with committee")
)

// RecoverNodeEpoch scans the persistent vault to detect the highest active epoch and recover state
func RecoverNodeEpoch(
	committeeID string,
	shareStore *vault.ShareStore,
	expectedEpoch uint64,
) (uint64, error) {
	if shareStore == nil {
		return 1, nil
	}

	// Try loading from expectedEpoch downward
	for epoch := expectedEpoch; epoch >= 1; epoch-- {
		meta, share, _, err := shareStore.LoadShare(committeeID, epoch, epoch)
		if err == nil && meta != nil && share != nil && meta.State == "ACTIVE" {
			log.Printf("[Proactive Recovery] Successfully recovered active share for committee %s at epoch %d",
				committeeID, epoch)
			return epoch, nil
		}
	}

	return 1, nil
}

// AbortInterruptedEpoch safely cleans up temporary session state if a node crashes mid-transition
func (m *Manager) AbortInterruptedEpoch() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.State == EpochStateRefreshing {
		m.State = EpochStateAborted
		if m.CurrentSession != nil {
			m.CurrentSession.State = RefreshStateFailed
			m.CurrentSession.Error = "phase transition aborted due to process restart or network timeout"
		}
		log.Printf("[Proactive Manager - %s] Interrupted epoch %d transition aborted safely",
			m.NodeID, m.ActiveEpoch+1)
	}
}
