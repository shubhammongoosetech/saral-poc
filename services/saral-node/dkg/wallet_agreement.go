package dkg

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"time"
)

const MessageTypeWalletAgreement = "DKG_WALLET_AGREEMENT"

const (
	walletDealerReady = "dealer_ready"
	walletPrepare     = "prepare"
	walletCommit      = "commit"
	walletNewView     = "new_view"
)

// Each attestation is scoped to the complete wallet DKG identity and signed
// independently of the relay, since votes may be forwarded as certificates.
type WalletVote struct {
	Scope     string          `json:"scope"`
	Phase     string          `json:"phase"`
	View      uint64          `json:"view"`
	Sender    string          `json:"sender"`
	Dealer    string          `json:"dealer,omitempty"`
	Digest    string          `json:"digest,omitempty"`
	Prepared  *walletPrepared `json:"prepared,omitempty"`
	Signature string          `json:"signature,omitempty"`
}

type walletDealerCertificate struct {
	Dealer string       `json:"dealer"`
	Digest string       `json:"digest"`
	Votes  []WalletVote `json:"votes"`
}

type walletValue []walletDealerCertificate

type walletPrepared struct {
	View  uint64       `json:"view"`
	Value walletValue  `json:"value"`
	Votes []WalletVote `json:"votes"`
}

type WalletProposal struct {
	Scope     string       `json:"scope"`
	View      uint64       `json:"view"`
	Leader    string       `json:"leader"`
	Value     walletValue  `json:"value"`
	NewView   []WalletVote `json:"newView,omitempty"`
	Signature string       `json:"signature,omitempty"`
}

type WalletAgreementMessage struct {
	SessionID string             `json:"sessionId"`
	Vote      *WalletVote        `json:"vote,omitempty"`
	Proposal  *WalletProposal    `json:"proposal,omitempty"`
	Decision  *walletCommitProof `json:"decision,omitempty"`
}

type walletCommitProof struct {
	Prepared *walletPrepared `json:"prepared"`
	Commits  []WalletVote    `json:"commits"`
}

type walletAgreementCheckpoint struct {
	View     uint64                `json:"view"`
	Prepared *walletPrepared       `json:"prepared,omitempty"`
	Proposal *WalletProposal       `json:"proposal,omitempty"`
	Own      map[string]WalletVote `json:"own"`
	Dealers  map[string]WalletVote `json:"dealers"`
	Decision *walletCommitProof    `json:"decision,omitempty"`
}

// A single-slot PBFT-style agreement on a certified set of completed dealers.
// A replica persists its view, highest prepared proof, and own votes before
// sending. A later leader is constrained by the highest prepared proof in a
// quorum of signed view changes.
type walletAgreement struct {
	session  *Session
	scope    string
	keys     map[string]ed25519.PublicKey
	sign     func([]byte) string
	quorum   int
	mu       sync.Mutex
	started  bool
	failed   error
	deadline time.Time
	state    walletAgreementCheckpoint
	witness  map[string]map[string]WalletVote
	votes    map[uint64]map[string]map[string]WalletVote
}

func newWalletAgreement(s *Session, sign func([]byte) string, keyFor func(string) string) (*walletAgreement, error) {
	if sign == nil || keyFor == nil {
		return nil, fmt.Errorf("committee signing keys are unavailable")
	}
	keys := make(map[string]ed25519.PublicKey, s.N)
	used := make(map[string]bool, s.N)
	for _, id := range s.Committee {
		key, err := hex.DecodeString(keyFor(id))
		if err != nil || len(key) != ed25519.PublicKeySize || used[string(key)] {
			return nil, fmt.Errorf("invalid or missing committee signing key")
		}
		keys[id] = ed25519.PublicKey(key)
		used[string(key)] = true
	}
	a := &walletAgreement{
		session: s, scope: s.walletScope(), keys: keys, sign: sign, quorum: s.N - s.T,
		witness: make(map[string]map[string]WalletVote), votes: make(map[uint64]map[string]map[string]WalletVote),
		state: walletAgreementCheckpoint{Own: make(map[string]WalletVote), Dealers: make(map[string]WalletVote)},
	}
	probe := []byte("saral/wallet-dkg/signer/v1/" + a.scope)
	if !a.verifySignature(s.SelfID, sign(probe), probe) {
		return nil, fmt.Errorf("local wallet agreement signing key does not match committee enrollment")
	}
	data, err := s.ShareStore.LoadProtocolState(a.scope, "agreement-v1")
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &a.state); err != nil {
			return nil, err
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	if a.state.Own == nil || a.state.Dealers == nil {
		return nil, fmt.Errorf("invalid agreement checkpoint")
	}
	for _, vote := range a.state.Dealers {
		a.recordVote(vote)
	}
	for _, vote := range a.state.Own {
		a.recordVote(vote)
	}
	return a, nil
}

func (a *walletAgreement) persist() error {
	data, err := json.Marshal(a.state)
	if err == nil {
		err = a.session.ShareStore.SaveProtocolState(a.scope, "agreement-v1", data)
	}
	if err != nil {
		a.failed = err
	}
	return err
}

func (a *walletAgreement) leader(view uint64) string {
	return a.session.Committee[view%uint64(a.session.N)]
}

func walletAgreementDigest(data any) string {
	encoded, _ := json.Marshal(data)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func valueDigest(value walletValue) string {
	identity := make([][2]string, 0, len(value))
	for _, cert := range value {
		identity = append(identity, [2]string{cert.Dealer, cert.Digest})
	}
	return walletAgreementDigest(identity)
}

func walletVotePayload(v WalletVote) []byte {
	v.Signature = ""
	data, _ := json.Marshal(v)
	return append([]byte("saral/wallet-dkg/vote/v1/"), data...)
}

func walletProposalPayload(p WalletProposal) []byte {
	p.Signature = ""
	data, _ := json.Marshal(p)
	return append([]byte("saral/wallet-dkg/proposal/v1/"), data...)
}

func (a *walletAgreement) signVote(v WalletVote) WalletVote {
	v.Scope, v.Sender = a.scope, a.session.SelfID
	v.Signature = a.sign(walletVotePayload(v))
	return v
}

func (a *walletAgreement) verifySignature(sender, signature string, data []byte) bool {
	pub := a.keys[sender]
	sig, err := hex.DecodeString(signature)
	return len(pub) == ed25519.PublicKeySize && err == nil && ed25519.Verify(pub, data, sig)
}

func validWalletDigest(digest string) bool {
	data, err := hex.DecodeString(digest)
	return err == nil && len(data) == sha256.Size
}

func (a *walletAgreement) verifyVote(v WalletVote) bool {
	if v.Scope != a.scope || !a.verifySignature(v.Sender, v.Signature, walletVotePayload(v)) {
		return false
	}
	switch v.Phase {
	case walletDealerReady:
		return v.View == 0 && v.Prepared == nil && validWalletDigest(v.Digest) && a.keys[v.Dealer] != nil
	case walletPrepare, walletCommit:
		return v.Dealer == "" && v.Prepared == nil && validWalletDigest(v.Digest)
	case walletNewView:
		return v.View > 0 && v.Dealer == "" && v.Digest == "" &&
			(v.Prepared == nil || (v.Prepared.View < v.View && a.verifyPrepared(v.Prepared)))
	default:
		return false
	}
}

func (a *walletAgreement) verifyValue(value walletValue) bool {
	if len(value) < a.session.T+1 || len(value) > a.session.N {
		return false
	}
	last := ""
	for _, cert := range value {
		if cert.Dealer <= last || a.keys[cert.Dealer] == nil || len(cert.Votes) != a.quorum {
			return false
		}
		seen := make(map[string]bool, a.quorum)
		for _, v := range cert.Votes {
			if seen[v.Sender] || v.Phase != walletDealerReady || v.Dealer != cert.Dealer ||
				v.Digest != cert.Digest || !a.verifyVote(v) {
				return false
			}
			seen[v.Sender] = true
		}
		last = cert.Dealer
	}
	return true
}

func (a *walletAgreement) verifyPrepared(prepared *walletPrepared) bool {
	if len(prepared.Votes) != a.quorum || !a.verifyValue(prepared.Value) {
		return false
	}
	digest := valueDigest(prepared.Value)
	seen := make(map[string]bool, a.quorum)
	for _, v := range prepared.Votes {
		if seen[v.Sender] || v.Phase != walletPrepare || v.View != prepared.View ||
			v.Digest != digest || !a.verifyVote(v) {
			return false
		}
		seen[v.Sender] = true
	}
	return true
}

func (a *walletAgreement) verifyDecision(proof *walletCommitProof) bool {
	if proof.Prepared == nil || len(proof.Commits) != a.quorum || !a.verifyPrepared(proof.Prepared) {
		return false
	}
	digest := valueDigest(proof.Prepared.Value)
	seen := make(map[string]bool, a.quorum)
	for _, v := range proof.Commits {
		if seen[v.Sender] || v.Phase != walletCommit || v.View != proof.Prepared.View ||
			v.Digest != digest || !a.verifyVote(v) {
			return false
		}
		seen[v.Sender] = true
	}
	return true
}

func (a *walletAgreement) verifyProposal(p *WalletProposal) bool {
	if p.Scope != a.scope || p.Leader != a.leader(p.View) || !a.verifyValue(p.Value) ||
		!a.verifySignature(p.Leader, p.Signature, walletProposalPayload(*p)) {
		return false
	}
	if p.View == 0 {
		return len(p.NewView) == 0
	}
	if len(p.NewView) != a.quorum {
		return false
	}
	seen := make(map[string]bool, a.quorum)
	for _, v := range p.NewView {
		if seen[v.Sender] || v.Phase != walletNewView || v.View != p.View || !a.verifyVote(v) {
			return false
		}
		seen[v.Sender] = true
	}
	highest := highestWalletPrepared(p.NewView)
	return highest == nil || valueDigest(highest.Value) == valueDigest(p.Value)
}

func highestWalletPrepared(votes []WalletVote) *walletPrepared {
	var highest *walletPrepared
	for _, v := range votes {
		if v.Prepared != nil && (highest == nil || v.Prepared.View > highest.View) {
			highest = v.Prepared
		}
	}
	return highest
}

func (a *walletAgreement) recordVote(v WalletVote) {
	if v.Phase == walletDealerReady {
		if a.witness[v.Dealer] == nil {
			a.witness[v.Dealer] = make(map[string]WalletVote)
		}
		if _, exists := a.witness[v.Dealer][v.Sender]; !exists {
			a.witness[v.Dealer][v.Sender] = v
		}
		return
	}
	if a.votes[v.View] == nil {
		a.votes[v.View] = make(map[string]map[string]WalletVote)
	}
	if a.votes[v.View][v.Phase] == nil {
		a.votes[v.View][v.Phase] = make(map[string]WalletVote)
	}
	if _, exists := a.votes[v.View][v.Phase][v.Sender]; !exists {
		a.votes[v.View][v.Phase][v.Sender] = v
	}
}

func quorumVotes(votes map[string]WalletVote, digest string, count int) []WalletVote {
	result := make([]WalletVote, 0, len(votes))
	for _, v := range votes {
		if v.Digest == digest {
			result = append(result, v)
		}
	}
	if len(result) < count {
		return nil
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Sender < result[j].Sender })
	return result[:count]
}

func (a *walletAgreement) candidate() walletValue {
	var value walletValue
	for _, dealer := range a.session.Committee {
		witness := a.witness[dealer]
		for _, v := range witness {
			if votes := quorumVotes(witness, v.Digest, a.quorum); votes != nil {
				value = append(value, walletDealerCertificate{Dealer: dealer, Digest: v.Digest, Votes: votes})
				break
			}
		}
		if len(value) == a.session.T+1 {
			return value
		}
	}
	return nil
}

func (a *walletAgreement) recordOwnVote(v WalletVote) error {
	v = a.signVote(v)
	if v.Phase == walletDealerReady {
		a.state.Dealers[v.Dealer] = v
	} else {
		a.state.Own[v.Phase] = v
	}
	if err := a.persist(); err != nil {
		return err
	}
	a.recordVote(v)
	return nil
}

func (a *walletAgreement) enterView(view uint64, now time.Time) error {
	a.state.View = view
	a.state.Proposal = nil
	a.state.Own = make(map[string]WalletVote)
	for old := range a.votes {
		if old < view {
			delete(a.votes, old)
		}
	}
	a.deadline = now.Add(walletViewTimeout(view))
	return a.recordOwnVote(WalletVote{Phase: walletNewView, View: view, Prepared: a.state.Prepared})
}

func walletViewTimeout(view uint64) time.Duration {
	return 4 * time.Second << min(view, 5)
}

func (a *walletAgreement) advance(now time.Time) error {
	if a.state.Decision != nil || !a.started {
		return nil
	}
	view := a.state.View
	if next := a.votes[view+1][walletNewView]; len(next) >= a.session.T+1 ||
		(!now.Before(a.deadline) && (view != 0 || a.candidate() != nil)) {
		if err := a.enterView(view+1, now); err != nil {
			return err
		}
		view = a.state.View
	}
	if a.state.Proposal == nil && a.leader(view) == a.session.SelfID {
		newView := quorumVotes(a.votes[view][walletNewView], "", a.quorum)
		if view == 0 || newView != nil {
			value := a.candidate()
			if highest := highestWalletPrepared(newView); highest != nil {
				value = highest.Value
			}
			if value != nil {
				p := &WalletProposal{Scope: a.scope, View: view, Leader: a.session.SelfID, Value: value, NewView: newView}
				p.Signature = a.sign(walletProposalPayload(*p))
				a.state.Proposal = p
				if err := a.persist(); err != nil {
					return err
				}
			}
		}
	}
	p := a.state.Proposal
	if p == nil {
		return nil
	}
	digest := valueDigest(p.Value)
	if _, sent := a.state.Own[walletPrepare]; !sent {
		if err := a.recordOwnVote(WalletVote{Phase: walletPrepare, View: view, Digest: digest}); err != nil {
			return err
		}
	}
	if _, sent := a.state.Own[walletCommit]; !sent {
		if votes := quorumVotes(a.votes[view][walletPrepare], digest, a.quorum); votes != nil {
			a.state.Prepared = &walletPrepared{View: view, Value: p.Value, Votes: votes}
			if err := a.recordOwnVote(WalletVote{Phase: walletCommit, View: view, Digest: digest}); err != nil {
				return err
			}
		}
	}
	if a.state.Prepared != nil && a.state.Prepared.View == view {
		if commits := quorumVotes(a.votes[view][walletCommit], digest, a.quorum); commits != nil {
			a.state.Decision = &walletCommitProof{Prepared: a.state.Prepared, Commits: commits}
			return a.persist()
		}
	}
	return nil
}

func (a *walletAgreement) receive(msg *WalletAgreementMessage) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed != nil {
		return a.failed
	}
	if msg.Decision != nil {
		if msg.Vote != nil || msg.Proposal != nil || !a.verifyDecision(msg.Decision) {
			return fmt.Errorf("invalid wallet decision proof")
		}
		if a.state.Decision == nil {
			a.state.Decision = msg.Decision
			return a.persist()
		}
		if valueDigest(a.state.Decision.Prepared.Value) != valueDigest(msg.Decision.Prepared.Value) {
			return fmt.Errorf("conflicting wallet decision proof")
		}
		return nil
	}
	if (msg.Vote == nil) == (msg.Proposal == nil) {
		return fmt.Errorf("invalid wallet agreement message")
	}
	now := time.Now()
	view := a.state.View
	if p := msg.Proposal; p != nil {
		if p.View < view {
			return nil
		}
		if !a.verifyProposal(p) {
			return fmt.Errorf("invalid wallet agreement proposal")
		}
		if p.View > view {
			if a.state.Decision != nil {
				return nil
			}
			if err := a.enterView(p.View, now); err != nil {
				return err
			}
		}
		if a.state.Proposal == nil {
			a.state.Proposal = p
			if err := a.persist(); err != nil {
				return err
			}
		}
	} else {
		v := *msg.Vote
		if v.Phase != walletDealerReady && v.View < view {
			return nil
		}
		if v.View > view+1 || !a.verifyVote(v) {
			return fmt.Errorf("invalid wallet agreement vote")
		}
		a.recordVote(v)
	}
	return a.advance(now)
}

func (a *walletAgreement) observeDealer(dealer, digest string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed != nil {
		return a.failed
	}
	if old, sent := a.state.Dealers[dealer]; sent {
		if old.Digest != digest {
			return fmt.Errorf("completed dealer changed its commitment")
		}
		return nil
	}
	if err := a.recordOwnVote(WalletVote{Phase: walletDealerReady, Dealer: dealer, Digest: digest}); err != nil {
		return err
	}
	return a.advance(time.Now())
}

func (a *walletAgreement) begin() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		return false
	}
	a.started = true
	a.deadline = time.Now().Add(walletViewTimeout(a.state.View))
	return true
}

func (a *walletAgreement) outbound() ([]WalletAgreementMessage, walletValue, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed != nil {
		return nil, nil, a.failed
	}
	if err := a.advance(time.Now()); err != nil {
		return nil, nil, err
	}
	session := a.session.SessionID
	if a.state.Decision != nil {
		return []WalletAgreementMessage{{SessionID: session, Decision: a.state.Decision}},
			slices.Clone(a.state.Decision.Prepared.Value), nil
	}
	messages := make([]WalletAgreementMessage, 0, len(a.state.Dealers)+len(a.state.Own)+1)
	if a.state.Proposal != nil {
		messages = append(messages, WalletAgreementMessage{SessionID: session, Proposal: a.state.Proposal})
	}
	for _, vote := range a.state.Dealers {
		messages = append(messages, WalletAgreementMessage{SessionID: session, Vote: &vote})
	}
	for _, vote := range a.state.Own {
		messages = append(messages, WalletAgreementMessage{SessionID: session, Vote: &vote})
	}
	return messages, nil, nil
}
