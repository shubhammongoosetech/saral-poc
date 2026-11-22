package dkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
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

	sessions     map[string]*Session
	mu           sync.RWMutex
	walletSign   func([]byte) string
	walletKeyFor func(string) string
}

// ConfigureWalletAgreement supplies the local identity and the pinned committee keys.
// Invoke before serving wallet DKG requests.
func (e *Engine) ConfigureWalletAgreement(sign func([]byte) string, keyFor func(string) string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.walletSign = sign
	e.walletKeyFor = keyFor
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
	sessionID, committeeID, walletID, keyID, userID, curveName, chainFamily string,
	n, k, t int,
	committee []string,
) (*Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	curve, err := cryptography.ParseCurve(curveName)
	if err != nil {
		return nil, err
	}
	bound := walletID != "" || keyID != "" || userID != ""
	if !vault.ValidRecordID(sessionID) || !vault.ValidRecordID(committeeID) {
		return nil, fmt.Errorf("invalid DKG session or committee identifier")
	}
	if len(committee) != n {
		return nil, fmt.Errorf("participant count does not match committee")
	}
	if bound {
		validChain := (curve == cryptography.CurveSecp256k1 && (chainFamily == "mst" || chainFamily == "bitcoin")) ||
			(curve == cryptography.CurveEd25519 && chainFamily == "solana")
		if !validChain || !vault.ValidRecordID(walletID) || !vault.ValidRecordID(keyID) || !vault.ValidRecordID(userID) {
			return nil, fmt.Errorf("invalid wallet key binding")
		}
		domain := strings.ToLower(e.Domain)
		if n != 5 || k != 3 || t != 1 || !slices.Contains([]string{"foundation", "public", "private"}, domain) ||
			committeeID != "committee-"+domain {
			return nil, fmt.Errorf("wallet DKG requires a 3-of-5 committee in the local domain")
		}
		for index, node := range committee {
			if node != fmt.Sprintf("saral-%s-%d", domain, index+1) {
				return nil, fmt.Errorf("wallet DKG committee members do not match the local domain")
			}
		}
		if !e.ShareStore.Persistent() {
			return nil, fmt.Errorf("a persistent share vault is required for wallet DKG")
		}
	} else if curve != cryptography.CurveP256 {
		return nil, fmt.Errorf("wallet curves require a wallet key binding")
	}
	if sess, exists := e.sessions[sessionID]; exists {
		if sess.WalletID != walletID || sess.KeyID != keyID || sess.UserBindingID != userID || sess.Curve != curve ||
			sess.ChainFamily != chainFamily || sess.CommitteeID != committeeID || sess.N != n || sess.K != k || sess.T != t ||
			!slices.Equal(sess.Committee, committee) {
			return nil, fmt.Errorf("existing DKG session has different bindings")
		}
		return sess, nil
	}

	participants := make(map[string]bool, n)
	for _, member := range committee {
		if !vault.ValidRecordID(member) || participants[member] {
			return nil, fmt.Errorf("invalid or duplicate DKG participant")
		}
		participants[member] = true
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
	sess.Curve = curve
	sess.ChainFamily = chainFamily

	if bound {
		meta, share, blind, err := e.ShareStore.LoadKeyShare(keyID, sess.Epoch)
		switch {
		case err == nil:
			defer share.Zero()
			defer blind.Zero()
			if !matchesWalletRecord(meta, sess, e.NodeID) || (meta.State != "ACTIVE" && meta.State != "STAGED") {
				return nil, fmt.Errorf("existing key share has different bindings")
			}
			if meta.State == "STAGED" {
				if err := sess.activateWalletShare(*meta, share, blind); err != nil {
					return nil, err
				}
			}
			sess.State = StateCompleted
		case !errors.Is(err, vault.ErrShareNotFound):
			return nil, fmt.Errorf("could not check existing wallet key share: %w", err)
		}
		if sess.State != StateCompleted {
			if err := sess.reserveWalletSession(); err != nil {
				return nil, err
			}
			sess.walletAgreement, err = newWalletAgreement(sess, e.walletSign, e.walletKeyFor)
			if err != nil {
				return nil, err
			}
		} else {
			// A completed share predating the agreement checkpoint keeps its
			// original identity and remains available for public derivation.
			if e.walletSign != nil && e.walletKeyFor != nil {
				a, err := newWalletAgreement(sess, e.walletSign, e.walletKeyFor)
				if err == nil && a.state.Decision != nil {
					sess.walletAgreement = a
				}
			}
			if sess.walletAgreement == nil {
				e.sessions[sessionID] = sess
				return sess, nil
			}
		}
	}
	for _, existing := range e.sessions {
		if bound && existing.KeyID == keyID {
			return nil, fmt.Errorf("key already belongs to a different DKG session")
		}
	}

	log.Printf("[DKG Engine - %s] Session %s created for committee %s (n=%d, k=%d, t=%d, index=%d, wallet=%s, key=%s)",
		e.NodeID, sessionID, committeeID, n, k, t, selfIndex, walletID, keyID)

	// Pre-create the expected AVSS recipient sessions for all committee members
	if e.AVSSEngine != nil {
		for _, member := range committee {
			subSessID := fmt.Sprintf("dkg-%s-contrib-%s", sessionID, member)
			if _, err := e.AVSSEngine.CreateSessionForCurve(subSessID, committeeID, member, 1, n, k, t, committee, curve); err != nil {
				return nil, err
			}
		}
	}

	e.sessions[sessionID] = sess
	return sess, nil
}

func matchesWalletRecord(meta *vault.ShareRecordMetadata, sess *Session, nodeID string) bool {
	return meta.RecordVersion == 2 && meta.WalletID == sess.WalletID && meta.UserBindingID == sess.UserBindingID &&
		meta.KeyID == sess.KeyID && meta.DKGSessionID == sess.SessionID && meta.CommitteeID == sess.CommitteeID &&
		meta.NodeID == nodeID && meta.NodeIndex == sess.SelfIndex && meta.Epoch == sess.Epoch &&
		meta.Curve == string(sess.Curve) && meta.ChainFamily == sess.ChainFamily && meta.Threshold == sess.K &&
		meta.MasterSigningPublicKeyHash != ""
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

func (e *Engine) HasPersistedWalletShare(sessionID, keyID string) bool {
	if e.ShareStore == nil || !vault.ValidRecordID(sessionID) || !vault.ValidRecordID(keyID) {
		return false
	}
	meta, share, blind, err := e.ShareStore.LoadKeyShare(keyID, 1)
	if err != nil {
		return false
	}
	share.Zero()
	blind.Zero()
	return meta.RecordVersion == 2 && meta.KeyID == keyID && meta.DKGSessionID == sessionID &&
		meta.UserBindingID != "" && meta.WalletID != "" && meta.NodeID == e.NodeID &&
		meta.State == "ACTIVE" && meta.MasterSigningPublicKeyHash != ""
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

	if dealerPkg == nil {
		if sess.walletAgreement == nil {
			return nil
		}
		contribution, err := sess.loadWalletAnnouncement()
		if err != nil {
			return err
		}
		if sess.walletAgreement.begin() {
			e.replayWalletAVSS(sess)
			go e.runWalletAgreement(sess, nil, contribution)
		}
		return nil
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
		Timestamp:        time.Now().UnixMilli(),
	}
	if sess.UserBindingID != "" {
		signing := sess.Curve.BaseMult(dealerPkg.Secret)
		announcement, response, err := cryptography.ProveSigningCommitment(
			sessionID+":"+e.NodeID, dealerPkg.CommitmentMatrix.SecretCommitment(), signing, dealerPkg.BlindSecret,
		)
		if err != nil {
			return err
		}
		contribMsg.PublicKeyCommitment = signing.Hex()
		contribMsg.ProofAnnouncement = announcement
		contribMsg.ProofResponse = response
		if err := sess.saveWalletAnnouncement(contribMsg); err != nil {
			return err
		}
	}
	e.broadcastDKG(sess.Committee, MessageTypeDKGContribution, contribMsg)

	// 2. Delegate AVSS distribution to local AVSS engine
	if e.AVSSEngine != nil {
		e.AVSSEngine.DispatchDealerPackage(dealerPkg)
	}
	if agreement := sess.walletAgreement; agreement != nil && agreement.begin() {
		e.replayWalletAVSS(sess)
		go e.runWalletAgreement(sess, dealerPkg, contribMsg)
	}

	return nil
}

// OnAVSSSubprotocolCompleted is invoked when an AVSS subprotocol session completes
func (e *Engine) OnAVSSSubprotocolCompleted(subSessionID string, avssSess *avss.Session) {
	e.mu.RLock()
	var matched *Session
	for _, sess := range e.sessions {
		expectedID := fmt.Sprintf("dkg-%s-contrib-%s", sess.SessionID, avssSess.DealerID)
		if subSessionID == expectedID && sess.Curve == avssSess.Curve && sess.CommitteeID == avssSess.CommitteeID {
			matched = sess
			break
		}
	}
	e.mu.RUnlock()
	if matched != nil {
		matched.RecordCompletedSharing(avssSess.DealerID, avssSess)
		e.dealerCompleted(matched, avssSess.DealerID)
	}
}

func (e *Engine) maybeProposeQualifiedSet(sess *Session) {
	if len(sess.GetCandidateQualifiedSet()) < sess.N-sess.T {
		return
	}
	sess.mu.Lock()
	if sess.proposed {
		sess.mu.Unlock()
		return
	}
	sess.proposed = true
	sess.mu.Unlock()
	go func() {
		if len(sess.GetCandidateQualifiedSet()) < sess.N {
			time.Sleep(100 * time.Millisecond)
		}
		e.proposeQualifiedSet(sess, &proactive.AgreementProposeMessage{
			SessionID: sess.SessionID, CommitteeID: sess.CommitteeID, Epoch: sess.Epoch,
			ProposerID: e.NodeID, CandidateSet: sess.GetCandidateQualifiedSet(),
		})
	}()
}

func (e *Engine) proposeQualifiedSet(sess *Session, propMsg *proactive.AgreementProposeMessage) {
	echo, err := sess.Agreement.ProcessProposal(propMsg)
	if err == nil && echo != nil {
		_ = e.HandleAgreementEcho(echo)
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
			_ = e.HandleAgreementEcho(echo)
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

	dealerIndex := avss.NodeIndexInCommittee(sess.Committee, msg.DealerID)
	if msg.CommitteeID != sess.CommitteeID || dealerIndex < 1 || dealerIndex != msg.DealerIndex || len(msg.CommitmentMatrix) != sess.K {
		return fmt.Errorf("invalid DKG contribution scope")
	}
	cm, err := avss.ParseCommitmentMatrixForCurve(msg.CommitmentMatrix, sess.Curve)
	if err != nil {
		return fmt.Errorf("failed to parse peer commitment matrix: %w", err)
	}

	if cm.Cols != sess.K {
		return fmt.Errorf("invalid DKG commitment dimensions")
	}
	if sess.UserBindingID != "" {
		signing, err := sess.Curve.ParsePoint(msg.PublicKeyCommitment)
		if err != nil || !cryptography.VerifySigningCommitment(
			sess.SessionID+":"+msg.DealerID, cm.SecretCommitment(), signing, msg.ProofAnnouncement, msg.ProofResponse,
		) {
			return fmt.Errorf("invalid proof of DKG signing commitment")
		}
		sess.RecordVerifiedSigningKey(msg.DealerID, cm.SecretCommitment(), signing)
		e.dealerCompleted(sess, msg.DealerID)
		return nil
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
		_ = e.HandleAgreementReady(ready)
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
		_ = e.HandleAgreementReady(readyToSend)
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
		if sess := e.sessions[sessionID]; sess != nil && sess.UserBindingID == "" && sess.CommitteeID == committeeID {
			return sess
		}
		return nil
	}

	for _, sess := range e.sessions {
		state := sess.GetPublicView().State
		if sess.UserBindingID == "" && sess.CommitteeID == committeeID && state != StateCompleted && state != StateFailed {
			return sess
		}
	}
	for _, sess := range e.sessions {
		if sess.UserBindingID == "" && sess.CommitteeID == committeeID {
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
	keyID, sessionID, committeeID, curveName string,
	epoch uint64,
) (string, int, uint64, string, *vault.ShareRecordMetadata, error) {
	if epoch == 0 {
		epoch = 1
	}
	curve, err := cryptography.ParseCurve(curveName)
	if err != nil {
		return "", 0, 0, "", nil, err
	}
	if !vault.ValidRecordID(sessionID) || (committeeID != "" && !vault.ValidRecordID(committeeID)) ||
		(keyID != "" && !vault.ValidRecordID(keyID)) || (curve != cryptography.CurveP256 && keyID == "") {
		return "", 0, 0, "", nil, fmt.Errorf("invalid DKG share scope")
	}

	if e.ShareStore != nil {
		recordID := sessionID
		if keyID != "" {
			recordID = keyID
		}
		meta, share, blind, err := e.ShareStore.LoadShare(recordID, epoch, 0)
		if err == nil {
			defer share.Zero()
			defer blind.Zero()
			if meta.DKGSessionID != sessionID || meta.CommitteeID != committeeID || meta.Epoch != epoch ||
				meta.NodeID != e.NodeID || meta.NodeIndex < 1 || meta.State != "ACTIVE" || share.Curve() != curve ||
				meta.KeyID != keyID || (curve != cryptography.CurveP256 && (meta.RecordVersion != 2 || meta.MasterSigningPublicKeyHash == "")) {
				return "", 0, 0, "", nil, fmt.Errorf("stored DKG share does not match request")
			}
			point := curve.BaseMult(share)
			if !point.IsOnCurve() {
				return "", 0, 0, "", nil, fmt.Errorf("invalid DKG public share")
			}
			return point.Hex(), meta.NodeIndex, meta.Epoch, meta.PublicSecretCommitment, meta, nil
		}
		if !errors.Is(err, vault.ErrShareNotFound) {
			return "", 0, 0, "", nil, err
		}
	}

	sess, err := e.GetSession(sessionID)
	if err != nil {
		return "", 0, 0, "", nil, err
	}
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	if sess.State != StateCompleted || sess.FinalShare == nil || sess.Epoch != epoch ||
		sess.KeyID != keyID || sess.CommitteeID != committeeID || sess.Curve != curve {
		return "", 0, 0, "", nil, fmt.Errorf("completed share does not match request")
	}
	point := curve.BaseMult(sess.FinalShare)
	if !point.IsOnCurve() {
		return "", 0, 0, "", nil, fmt.Errorf("invalid DKG public share")
	}
	commitment := sess.MasterSecretCommitment.Hex()
	meta := &vault.ShareRecordMetadata{
		WalletID: sess.WalletID, KeyID: sess.KeyID, UserBindingID: sess.UserBindingID,
		DKGSessionID: sess.SessionID, CommitteeID: sess.CommitteeID,
		NodeID: sess.SelfID, NodeIndex: sess.SelfIndex, Epoch: sess.Epoch,
		Curve: string(sess.Curve), ChainFamily: sess.ChainFamily,
	}
	if sess.UserBindingID != "" {
		meta.MasterSigningPublicKeyHash = signingPointHash(sess.MasterSigningPublicKey)
	}
	return point.Hex(), sess.SelfIndex, sess.Epoch, commitment, meta, nil
}
