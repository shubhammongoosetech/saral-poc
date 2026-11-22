package avss

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

type walletSharingCheckpoint struct {
	Send      SendMessage `json:"send"`
	Completed bool        `json:"completed"`
}

func (s *Session) walletCheckpointScope() string {
	data, _ := json.Marshal([]any{
		s.SessionID, s.CommitteeID, s.DealerID, s.SelfID, s.Curve, s.Epoch, s.K, s.T, s.Committee,
	})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (e *Engine) restoreWalletSharing(s *Session) error {
	if s.Curve == cryptography.CurveP256 || !e.ShareStore.Persistent() {
		return nil
	}
	data, err := e.ShareStore.LoadProtocolState(s.walletCheckpointScope(), "sharing-v1")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(data)
	var record walletSharingCheckpoint
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}
	if _, err := s.ProcessSendMessage(&record.Send); err != nil {
		return err
	}
	s.checkpointStage = 1
	if record.Completed {
		if err := s.FinalizeShare(); err != nil {
			return err
		}
		s.checkpointStage = 2
	}
	return nil
}

func (e *Engine) checkpointWalletSharing(s *Session) error {
	if s.Curve == cryptography.CurveP256 || !e.ShareStore.Persistent() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RowPoly == nil || s.ColPoly == nil || s.Commitments == nil {
		return nil
	}
	stage := 1
	completed := s.State == StateSharingCompleted
	if completed {
		stage = 2
	}
	if stage <= s.checkpointStage {
		return nil
	}
	record := walletSharingCheckpoint{
		Completed: completed,
		Send: SendMessage{
			SessionID: s.SessionID, CommitteeID: s.CommitteeID, DealerID: s.DealerID,
			RecipientID: s.SelfID, Epoch: s.Epoch, Commitments: s.Commitments.ToHexMatrix(),
			RowPoly: hexCoefficients(s.RowPoly), RowBlindPoly: hexCoefficients(s.RowBlindPoly),
			ColPoly: hexCoefficients(s.ColPoly), ColBlindPoly: hexCoefficients(s.ColBlindPoly),
		},
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := e.ShareStore.SaveProtocolState(s.walletCheckpointScope(), "sharing-v1", data); err != nil {
		return err
	}
	s.checkpointStage = stage
	return nil
}

func hexCoefficients(poly *Polynomial) []string {
	result := make([]string, len(poly.Coeffs))
	for i, c := range poly.Coeffs {
		result[i] = c.Hex()
	}
	return result
}

// ReplayWalletSharing re-sends this node's verified messages for each dealer
// and reports any durable completed sharing restored after a restart.
func (e *Engine) ReplayWalletSharing(sessionID string) {
	s, err := e.GetSession(sessionID)
	if err != nil || s.Curve == cryptography.CurveP256 {
		return
	}
	s.mu.Lock()
	echos := s.echoMessages()
	var readys []*ReadyMessage
	completed := s.State == StateSharingCompleted
	if s.SentReady || completed {
		readys = s.generateReadyMessages()
	}
	s.mu.Unlock()
	e.broadcastEchos(echos)
	e.broadcastReadys(readys)
	if completed {
		e.onSharingCompleted(s)
	}
}
