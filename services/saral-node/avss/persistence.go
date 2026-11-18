package avss

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SessionRecord stores non-secret session lifecycle metadata
type SessionRecord struct {
	SessionID              string   `json:"sessionId"`
	CommitteeID            string   `json:"committeeId"`
	DealerID               string   `json:"dealerId"`
	NodeID                 string   `json:"nodeId"`
	Epoch                  uint64   `json:"epoch"`
	N                      int      `json:"n"`
	K                      int      `json:"k"`
	T                      int      `json:"t"`
	State                  string   `json:"state"`
	PublicShareCommitment  string   `json:"publicShareCommitment,omitempty"`
	PublicSecretCommitment string   `json:"publicSecretCommitment,omitempty"`
	CreatedAt              int64    `json:"createdAt"`
	UpdatedAt              int64    `json:"updatedAt"`
	Error                  string   `json:"error,omitempty"`
}

// SessionStore handles thread-safe, crash-safe persistence of AVSS session records
type SessionStore struct {
	vaultDir string
	mu       sync.RWMutex
}

// NewSessionStore creates a new session store in the node's vault directory
func NewSessionStore(vaultDir string) *SessionStore {
	return &SessionStore{vaultDir: vaultDir}
}

func (s *SessionStore) getSessionPath(sessionID string) string {
	return filepath.Join(s.vaultDir, fmt.Sprintf("avss_session_%s.json", sessionID))
}

// SaveSession atomically persists session metadata to disk with 0600 permissions
func (s *SessionStore) SaveSession(rec *SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.vaultDir == "" {
		return nil
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}

	targetPath := s.getSessionPath(rec.SessionID)
	tmpPath := targetPath + ".tmp"

	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, targetPath)
}

// LoadSession reads a persisted session record from disk
func (s *SessionStore) LoadSession(sessionID string) (*SessionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.vaultDir == "" {
		return nil, os.ErrNotExist
	}

	targetPath := s.getSessionPath(sessionID)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, err
	}

	var rec SessionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

