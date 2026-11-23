//go:build test_only

package avss

import (
	"fmt"
)

// ExecuteTestReconstruction executes strictly isolated verifiable share reconstruction for test workflows
func (e *Engine) ExecuteTestReconstruction(
	sessionID string,
	shares []*ReconstructionShare,
) (*ReconstructedSecret, error) {
	e.mu.RLock()
	sess, exists := e.sessions[sessionID]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	if sess.Commitments == nil {
		return nil, fmt.Errorf("session %s has no verified commitment matrix", sessionID)
	}

	res, err := ReconstructSecret(shares, sess.Commitments, sess.K)
	if err != nil {
		return nil, err
	}

	return res, nil
}

