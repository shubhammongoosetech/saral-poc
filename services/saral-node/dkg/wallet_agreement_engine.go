package dkg

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
)

func (e *Engine) HandleWalletAgreement(msg *WalletAgreementMessage) error {
	sess, err := e.GetSession(msg.SessionID)
	if err != nil {
		return err
	}
	if sess.walletAgreement == nil {
		if sess.UserBindingID != "" && sess.GetPublicView().State == StateCompleted {
			return nil
		}
		return fmt.Errorf("wallet agreement is not available for this session")
	}
	return sess.walletAgreement.receive(msg)
}

func (e *Engine) dealerCompleted(sess *Session, dealerID string) {
	if sess.UserBindingID == "" {
		e.maybeProposeQualifiedSet(sess)
		return
	}
	agreement := sess.walletAgreement
	if agreement == nil {
		return
	}
	sess.mu.RLock()
	sharing := sess.CompletedSharings[dealerID]
	if sharing == nil || sharing.Commitments == nil ||
		!sess.signingCommitmentMatches(dealerID, sharing.Commitments.SecretCommitment()) {
		sess.mu.RUnlock()
		return
	}
	digest := avss.HashCommitments(sharing.Commitments.ToHexMatrix())
	sess.mu.RUnlock()
	if err := agreement.observeDealer(dealerID, digest); err != nil {
		log.Printf("[Wallet DKG] Persisting verified dealer completion failed: %v", err)
	}
}

func (s *Session) matchesWalletDecision(value walletValue) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dealers := make([]string, 0, len(value))
	for _, cert := range value {
		sharing := s.CompletedSharings[cert.Dealer]
		if sharing == nil || sharing.Commitments == nil || !s.signingCommitmentMatches(cert.Dealer, sharing.Commitments.SecretCommitment()) ||
			avss.HashCommitments(sharing.Commitments.ToHexMatrix()) != cert.Digest {
			return nil
		}
		dealers = append(dealers, cert.Dealer)
	}
	return dealers
}

func (e *Engine) replayWalletAVSS(sess *Session) {
	if e.AVSSEngine == nil {
		return
	}
	for _, dealer := range sess.Committee {
		id := fmt.Sprintf("dkg-%s-contrib-%s", sess.SessionID, dealer)
		e.AVSSEngine.ReplayWalletSharing(id)
	}
}

func (e *Engine) runWalletAgreement(sess *Session, dealer *avss.DealerPackage, contribution DKGContributionMessage) {
	agreement := sess.walletAgreement
	defer func() {
		agreement.mu.Lock()
		agreement.started = false
		agreement.mu.Unlock()
	}()

	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	nextShares := time.Now().Add(3 * time.Second)
	end := time.Now().Add(4 * time.Minute)
	var completed time.Time
	if sess.GetPublicView().State == StateCompleted {
		completed = time.Now()
	}
	busy := make(map[string]bool, sess.N)
	sent := make(chan string, sess.N)
	for now := range ticker.C {
		if !now.Before(end) || (!completed.IsZero() && now.Sub(completed) >= 15*time.Second) {
			return
		}
		messages, value, err := agreement.outbound()
		if err != nil {
			log.Printf("[Wallet DKG] Agreement stopped: %v", err)
			return
		}
		if len(value) > 0 && completed.IsZero() {
			if dealers := sess.matchesWalletDecision(value); dealers != nil {
				if err := sess.aggregateShares(dealers, true); err != nil {
					log.Printf("[Wallet DKG] Verified decision could not be persisted: %v", err)
				} else {
					completed = now
					dealer = nil
				}
			}
		}
		if !now.Before(nextShares) && e.AVSSEngine != nil {
			if contribution.SessionID != "" {
				e.broadcastDKG(sess.Committee, MessageTypeDKGContribution, contribution)
			}
			if dealer != nil {
				e.AVSSEngine.DispatchDealerPackage(dealer)
			}
			e.replayWalletAVSS(sess)
			nextShares = now.Add(3 * time.Second)
		}
		for len(sent) > 0 {
			delete(busy, <-sent)
		}
		if len(messages) == 0 || e.Relay == nil {
			continue
		}
		payloads := make([][]byte, 0, len(messages))
		for _, msg := range messages {
			if encoded, err := json.Marshal(msg); err == nil {
				payloads = append(payloads, encoded)
			}
		}
		for _, peer := range sess.Committee {
			if peer == e.NodeID || busy[peer] {
				continue
			}
			busy[peer] = true
			go func() {
				defer func() { sent <- peer }()
				for _, data := range payloads {
					if err := e.Relay.SendToNode(peer, e.Domain, MessageTypeWalletAgreement, data); err != nil {
						break
					}
				}
			}()
		}
	}
}
