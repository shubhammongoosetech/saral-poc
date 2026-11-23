package dkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/proactive"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

// Engine orchestrates Dealerless DKG sessions on a SARAL node
type Engine struct {
	NodeID     string
	Domain     string
	VaultDir   string
	ShareStore *vault.ShareStore
	AVSSEngine *avss.Engine
	Relay      avss.RelaySender

	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewEngine creates a new DKG engine instance
func NewEngine(
	nodeID, domain, vaultDir string,
	shareStore *vault.ShareStore,
	avssEngine *avss.Engine,
	relay avss.RelaySender,
) *Engine {
	return &Engine{
		NodeID:     nodeID,
		Domain:     domain,
		VaultDir:   vaultDir,
		ShareStore: shareStore,
		AVSSEngine: avssEngine,
		Relay:      relay,
		sessions:   make(map[string]*Session),
	}
}

// CreateSession initializes a new DKG session on the node
func (e *Engine) CreateSession(
	sessionID, committeeID string,
	n, k, t int,
	committee []string,
) (*Session, error) {
	return e.CreateSessionWithBinding(sessionID, committeeID, "", "", "", "", "", n, k, t, committee)
}

// CreateSessionWithBinding initializes a new DKG session with authenticated wallet and user ownership bindings
func (e *Engine) CreateSessionWithBinding(
	sessionID, committeeID, walletID, keyID, userID, curve, chainFamily string,
	n, k, t int,
	committee []string,
) (*Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if sess, exists := e.sessions[sessionID]; exists {
		return sess, nil
	}

	selfIndex := avss.NodeIndexInCommittee(committee, e.NodeID)
	if selfIndex == -1 {
		return nil, fmt.Errorf("node %s is not a member of committee %v", e.NodeID, committee)
	}

	sess, err := NewSession(sessionID, committeeID, e.NodeID, selfIndex, committee, n, k, t, e.ShareStore)
	if err != nil {
		return nil, err
	}

	sess.WalletID = walletID
	sess.KeyID = keyID
	sess.UserBindingID = userID
	if curve == "" {
		if strings.EqualFold(chainFamily, "solana") {
			curve = "ed25519"
		} else {
			curve = "secp256k1"
		}
	}
	sess.Curve = curve
	sess.ChainFamily = chainFamily

	e.sessions[sessionID] = sess
	log.Printf("[DKG Engine - %s] Session %s created for committee %s (n=%d, k=%d, t=%d, index=%d, wallet=%s, key=%s)",
		e.NodeID, sessionID, committeeID, n, k, t, selfIndex, walletID, keyID)

	// Pre-create the expected AVSS recipient sessions for all committee members
	if e.AVSSEngine != nil {
		for _, member := range committee {
			subSessID := fmt.Sprintf("dkg-%s-contrib-%s", sessionID, member)
			subSess, _ := e.AVSSEngine.CreateSession(subSessID, committeeID, member, 1, n, k, t, committee)
			if subSess != nil {
				subSess.Curve = sess.Curve
			}
		}
	}

	return sess, nil
}

// GetSession returns a DKG session by ID
func (e *Engine) GetSession(sessionID string) (*Session, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sess, exists := e.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrDKGSessionNotFound, sessionID)
	}
	return sess, nil
}

// StartContribution deals the local random contribution and broadcasts commitments
func (e *Engine) StartContribution(sessionID string) error {
	sess, err := e.GetSession(sessionID)
	if err != nil {
		return err
	}

	dealerPkg, err := sess.StartContribution()
	if err != nil {
		return err
	}

	log.Printf("[DKG Engine - %s] Generated local contribution for session %s (SecretCommit: %s)",
		e.NodeID, sessionID, dealerPkg.CommitmentMatrix.SecretCommitment().Hex()[:16]+"...")

	// 1. Broadcast DKG_CONTRIBUTION metadata to all committee members
	contribMsg := DKGContributionMessage{
		SessionID:        sessionID,
		CommitteeID:      sess.CommitteeID,
		DealerID:         e.NodeID,
		DealerIndex:      sess.SelfIndex,
		SecretCommitment: dealerPkg.CommitmentMatrix.SecretCommitment().Hex(),
		CommitmentMatrix: dealerPkg.CommitmentMatrix.ToHexMatrix(),
		Curve:            sess.Curve,
		Timestamp:        time.Now().UnixMilli(),
	}
	e.broadcastDKG(sess.Committee, MessageTypeDKGContribution, contribMsg)

	// 2. Delegate AVSS distribution to local AVSS engine
	go func() {
		subSessionID := fmt.Sprintf("dkg-%s-contrib-%s", sessionID, e.NodeID)
		subSess, _ := e.AVSSEngine.CreateSession(subSessionID, sess.CommitteeID, e.NodeID, 1, sess.N, sess.K, sess.T, sess.Committee)
		if subSess != nil {
			subSess.Curve = sess.Curve
		}
		_, err := e.AVSSEngine.StartDealerSharing(
			subSessionID, sess.CommitteeID, sess.Committee, sess.K,
			sess.LocalSecret, sess.LocalBlind,
		)
		if err != nil {
			log.Printf("[DKG Engine - %s] Error starting AVSS sub-sharing: %v", e.NodeID, err)
		}
	}()

	return nil
}

// OnAVSSSubprotocolCompleted is invoked when an AVSS subprotocol session completes
func (e *Engine) OnAVSSSubprotocolCompleted(subSessionID string, avssSess *avss.Session) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, sess := range e.sessions {
		expectedPrefix := fmt.Sprintf("dkg-%s-contrib-", sess.SessionID)
		if len(subSessionID) > len(expectedPrefix) && subSessionID[:len(expectedPrefix)] == expectedPrefix {
			dealerID := subSessionID[len(expectedPrefix):]
			sess.RecordCompletedSharing(dealerID, avssSess)
			log.Printf("[DKG Engine - %s] Recorded completed AVSS contribution from dealer %s in session %s (%d/%d verified)",
				e.NodeID, dealerID, sess.SessionID, len(sess.CompletedSharings), sess.N-sess.T)

			// If ready to propose qualified set, propose automatically
			if sess.CanProposeQualifiedSet() && !sess.Agreement.IsDecided && !sess.proposed {
				sess.proposed = true
				go func(s *Session) {
					// Wait up to 2 seconds for peer contributions to arrive (all N nodes in normal runs)
					deadline := time.Now().Add(2 * time.Second)
					for time.Now().Before(deadline) {
						s.mu.RLock()
						count := len(s.CompletedSharings)
						s.mu.RUnlock()
						if count >= s.N {
							break
						}
						time.Sleep(30 * time.Millisecond)
					}
					if s.Agreement.IsDecided {
						return
					}
					candidateSet := s.GetCandidateQualifiedSet()
					propMsg := &proactive.AgreementProposeMessage{
						SessionID:    s.SessionID,
						CommitteeID:  s.CommitteeID,
						Epoch:        s.Epoch,
						ProposerID:   e.NodeID,
						CandidateSet: candidateSet,
					}
					e.proposeQualifiedSet(s, propMsg)
				}(sess)
			}
			break
		}
	}
}

func (e *Engine) proposeQualifiedSet(sess *Session, propMsg *proactive.AgreementProposeMessage) {
	echo, err := sess.Agreement.ProcessProposal(propMsg)
	if err == nil && echo != nil {
		e.broadcastDKG(sess.Committee, proactive.MessageTypeAgreementEcho, echo)
	}
	e.broadcastDKG(sess.Committee, proactive.MessageTypeAgreementPropose, propMsg)

	if sess.Agreement.IsDecided {
		_ = e.finalizeDKG(sess, sess.Agreement.DecidedSet)
	}
}

// HandleAgreementPropose processes an incoming qualified set proposal
func (e *Engine) HandleAgreementPropose(msg *proactive.AgreementProposeMessage) error {
	sess := e.findSession(msg.SessionID, msg.CommitteeID)
	if sess == nil {
		return errors.New("no active DKG session for agreement propose")
	}

	go func() {
		// Wait until all dealers in candidateSet have finished AVSS sharing (up to 5s)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			allDone := true
			sess.mu.RLock()
			for _, dealerID := range msg.CandidateSet {
				if sub, exists := sess.CompletedSharings[dealerID]; !exists || sub == nil || sub.Share == nil {
					allDone = false
					break
				}
			}
			sess.mu.RUnlock()
			if allDone {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}

		echo, err := sess.Agreement.ProcessProposal(msg)
		if err != nil {
			log.Printf("[DKG Engine - %s] ProcessProposal error from %s: %v", e.NodeID, msg.ProposerID, err)
			return
		}
		if echo != nil {
			e.broadcastDKG(sess.Committee, proactive.MessageTypeAgreementEcho, echo)
		}

		if sess.Agreement.IsDecided {
			_ = e.finalizeDKG(sess, sess.Agreement.DecidedSet)
		}
	}()
	return nil
}

// HandleDKGInit processes an incoming DKG initialization broadcast
func (e *Engine) HandleDKGInit(msg *DKGInitMessage) error {
	_, err := e.CreateSession(msg.SessionID, msg.CommitteeID, msg.N, msg.K, msg.T, msg.Committee)
	if err != nil {
		return err
	}
	// Automatically start contribution
	go func() {
		_ = e.StartContribution(msg.SessionID)
	}()
	return nil
}

// HandleDKGContribution processes an incoming DKG contribution announcement from a peer
func (e *Engine) HandleDKGContribution(msg *DKGContributionMessage) error {
	sess, err := e.GetSession(msg.SessionID)
	if err != nil {
		return err
	}

	curve := sess.Curve
	if curve == "" {
		curve = msg.Curve
	}
	if curve == "" {
		curve = "nist-p256"
	}

	cm, err := avss.ParseCommitmentMatrixFromHexForCurve(msg.CommitmentMatrix, curve)
	if err != nil {
		return fmt.Errorf("failed to parse peer commitment matrix: %w", err)
	}

	sess.RecordPeerCommitment(msg.DealerID, cm)
	return nil
}

// HandleAgreementEcho processes an agreement echo for the qualified set
func (e *Engine) HandleAgreementEcho(echo *proactive.AgreementEchoMessage) error {
	sess := e.findSession(echo.SessionID, echo.CommitteeID)
	if sess == nil {
		return errors.New("no active DKG session for agreement echo")
	}

	ready, err := sess.Agreement.ProcessEcho(echo)
	if err != nil {
		return err
	}
	if ready != nil {
		e.broadcastDKG(sess.Committee, proactive.MessageTypeAgreementReady, ready)
	}
	return nil
}

// HandleAgreementReady processes an agreement ready message and checks for consensus decision
func (e *Engine) HandleAgreementReady(ready *proactive.AgreementReadyMessage) error {
	sess := e.findSession(ready.SessionID, ready.CommitteeID)
	if sess == nil {
		return errors.New("no active DKG session for agreement ready")
	}

	decidedSet, decided, readyToSend, err := sess.Agreement.ProcessReady(ready)
	if err != nil {
		return err
	}

	if readyToSend != nil {
		e.broadcastDKG(sess.Committee, proactive.MessageTypeAgreementReady, readyToSend)
	}

	if decided {
		return e.finalizeDKG(sess, decidedSet)
	}
	return nil
}

// HandleAgreementVote processes an ABBA vote message
func (e *Engine) HandleAgreementVote(msg *proactive.AgreementVoteMessage) error {
	sess := e.findSession(msg.SessionID, msg.CommitteeID)
	if sess == nil {
		return errors.New("no active DKG session for agreement vote")
	}

	nextVote, coinMsg, decided, decidedSet, err := sess.Agreement.ProcessVote(msg)
	if err != nil {
		return err
	}

	if nextVote != nil {
		e.broadcastDKG(sess.Committee, proactive.MessageTypeAgreementVote, nextVote)
	}
	if coinMsg != nil {
		e.broadcastDKG(sess.Committee, proactive.MessageTypeAgreementCoinShare, coinMsg)
	}

	if decided {
		return e.finalizeDKG(sess, decidedSet)
	}
	return nil
}

// HandleAgreementCoinShare processes an incoming threshold coin share
func (e *Engine) HandleAgreementCoinShare(msg *proactive.AgreementCoinShareMessage) error {
	sess := e.findSession(msg.SessionID, msg.CommitteeID)
	if sess == nil {
		return errors.New("no active DKG session for agreement coin share")
	}

	nextVote, decided, decidedSet, err := sess.Agreement.ProcessCoinShare(msg)
	if err != nil {
		return err
	}

	if nextVote != nil {
		e.broadcastDKG(sess.Committee, proactive.MessageTypeAgreementVote, nextVote)
	}

	if decided {
		return e.finalizeDKG(sess, decidedSet)
	}
	return nil
}

func (e *Engine) finalizeDKG(sess *Session, agreedQUAL []string) error {
	log.Printf("[DKG Engine - %s] AGREEMENT DECIDED on Qualified Set QUAL*=%v", e.NodeID, agreedQUAL)

	if err := sess.AggregateShares(agreedQUAL); err != nil {
		log.Printf("[DKG Engine - %s] Failed to aggregate shares: %v", e.NodeID, err)
		return err
	}

	log.Printf("[DKG Engine - %s] DKG COMPLETED! Public Key: %s, Local Share Commitment: %s",
		e.NodeID, sess.MasterPublicKey.Hex()[:16]+"...", sess.FinalShareCommit.Hex()[:16]+"...")

	// Broadcast completion notification
	notify := DKGCompleteNotification{
		SessionID:       sess.SessionID,
		CommitteeID:     sess.CommitteeID,
		NodeID:          e.NodeID,
		QualifiedSet:    agreedQUAL,
		MasterPublicKey: sess.MasterPublicKey.Hex(),
		Timestamp:       time.Now().UnixMilli(),
	}
	e.broadcastDKG(sess.Committee, MessageTypeDKGComplete, notify)
	return nil
}

func (e *Engine) findSession(sessionID, committeeID string) *Session {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if sessionID != "" {
		if sess, exists := e.sessions[sessionID]; exists {
			return sess
		}
	}

	for _, sess := range e.sessions {
		if sess.CommitteeID == committeeID && sess.State != StateCompleted && sess.State != StateFailed {
			return sess
		}
	}
	for _, sess := range e.sessions {
		if sess.CommitteeID == committeeID {
			return sess
		}
	}
	return nil
}

func (e *Engine) broadcastDKG(committee []string, msgType string, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	for _, target := range committee {
		if target == e.NodeID {
			continue
		}
		if e.Relay != nil {
			go func(t string, d []byte) {
				_ = e.Relay.SendToNode(t, "", msgType, d)
			}(target, data)
		}
	}
}

// GetAllSessionViews returns safe public views for all active sessions
func (e *Engine) GetAllSessionViews() []*DKGSessionPublicView {
	e.mu.RLock()
	defer e.mu.RUnlock()

	views := make([]*DKGSessionPublicView, 0, len(e.sessions))
	for _, sess := range e.sessions {
		views = append(views, sess.GetPublicView())
	}
	return views
}

// GetPublicShareContribution computes the node's public share point Y_i = x_i * G from its
// existing encrypted DKG share, WITHOUT EVER exposing or reconstructing the private scalar x_i.
func (e *Engine) GetPublicShareContribution(
	keyID, sessionID, committeeID, curve string,
	epoch uint64,
) (string, int, uint64, string, *vault.ShareRecordMetadata, error) {
	if strings.TrimSpace(curve) == "" {
		return "", 0, 0, "", nil, errors.New("curve parameter is strictly required")
	}
	normCurve := cryptography.NormalizeCurveName(curve)

	if epoch == 0 {
		epoch = 1
	}

	// 1. Try loading from encrypted vault
	if e.ShareStore != nil {
		idsToTry := []string{}
		if keyID != "" {
			idsToTry = append(idsToTry, keyID)
		}
		if sessionID != "" {
			idsToTry = append(idsToTry, sessionID)
		}
		if committeeID != "" {
			idsToTry = append(idsToTry, committeeID)
		}

		for _, idToTry := range idsToTry {
			meta, share, _, err := e.ShareStore.LoadShare(idToTry, epoch, 0)
			if err == nil && share != nil {
				defer share.Zero()

				vaultCurve := cryptography.NormalizeCurveName(meta.Curve)
				if vaultCurve != "" && vaultCurve != normCurve {
					return "", 0, 0, "", nil, fmt.Errorf("curve mismatch: vault record bound to %s, request requested %s", meta.Curve, curve)
				}

				ptHex, err := cryptography.ComputePublicContributionPoint(normCurve, share.Hex())
				if err != nil {
					return "", 0, 0, "", nil, fmt.Errorf("failed computing contribution point on curve %s: %w", normCurve, err)
				}
				return ptHex, meta.NodeIndex, meta.Epoch, meta.PublicSecretCommitment, meta, nil
			}
		}
	}

	// 2. Try loading from active in-memory sessions
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matchedSession *Session
	if sessionID != "" {
		matchedSession = e.sessions[sessionID]
	}
	if matchedSession == nil && keyID != "" {
		for _, s := range e.sessions {
			if s.KeyID == keyID {
				matchedSession = s
				break
			}
		}
	}
	if matchedSession == nil && committeeID != "" {
		for _, s := range e.sessions {
			if s.CommitteeID == committeeID {
				matchedSession = s
				break
			}
		}
	}

	if matchedSession != nil && matchedSession.FinalShare != nil {
		sessionCurve := cryptography.NormalizeCurveName(matchedSession.Curve)
		if sessionCurve != "" && sessionCurve != normCurve {
			return "", 0, 0, "", nil, fmt.Errorf("curve mismatch: session bound to %s, request requested %s", matchedSession.Curve, curve)
		}

		ptHex, err := cryptography.ComputePublicContributionPoint(normCurve, matchedSession.FinalShare.Hex())
		if err != nil {
			return "", 0, 0, "", nil, fmt.Errorf("failed computing contribution point on curve %s: %w", normCurve, err)
		}
		commit := ""
		if matchedSession.MasterSecretCommitment != nil {
			commit = matchedSession.MasterSecretCommitment.Hex()
		}
		meta := &vault.ShareRecordMetadata{
			WalletID:      matchedSession.WalletID,
			KeyID:         matchedSession.KeyID,
			UserBindingID: matchedSession.UserBindingID,
			DKGSessionID:  matchedSession.SessionID,
			CommitteeID:   matchedSession.CommitteeID,
			NodeIndex:     matchedSession.SelfIndex,
			Curve:         matchedSession.Curve,
		}
		return ptHex, matchedSession.SelfIndex, matchedSession.Epoch, commit, meta, nil
	}

	return "", 0, 0, "", nil, fmt.Errorf("no verified DKG share found on node %s for key %s / committee %s / session %s at epoch %d",
		e.NodeID, keyID, committeeID, sessionID, epoch)
}

