package rpc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
)

// DKGSessionMeta stores coordinator-level public tracking for a DKG session.
// STRICT PRIVACY GUARANTEE: Coordinators NEVER receive, handle, or store private secret shares.
type DKGSessionMeta struct {
	scope                  walletDKGScope
	SessionID              string                            `json:"sessionId"`
	CommitteeID            string                            `json:"committeeId"`
	Epoch                  uint64                            `json:"epoch"`
	N                      int                               `json:"n"`
	K                      int                               `json:"k"`
	T                      int                               `json:"t"`
	State                  string                            `json:"state"`
	Committee              []string                          `json:"committee"`
	QualifiedSet           []string                          `json:"qualifiedSet,omitempty"`
	MasterSigningPublicKey string                            `json:"masterSigningPublicKey,omitempty"` // Y = x*G
	MasterSecretCommitment string                            `json:"masterSecretCommitment,omitempty"` // C = x*G + x'*H
	MasterPublicKey        string                            `json:"masterPublicKey,omitempty"`        // signing key
	Curve                  string                            `json:"curve"`
	Participants           map[string]*DKGParticipantSummary `json:"participants"`
	CreatedAt              string                            `json:"createdAt"`
	UpdatedAt              string                            `json:"updatedAt"`
	Error                  string                            `json:"error,omitempty"`
}

// DKGParticipantSummary stores public participant progress on coordinator
type DKGParticipantSummary struct {
	NodeID            string `json:"nodeId"`
	NodeIndex         int    `json:"nodeIndex"`
	ContributionDealt bool   `json:"contributionDealt"`
	SecretCommitment  string `json:"secretCommitment,omitempty"`
	CompletedSharings int    `json:"completedSharings"`
	InQualifiedSet    bool   `json:"inQualifiedSet"`
	PublicShareCommit string `json:"publicShareCommit,omitempty"`
	Status            string `json:"status"`
}

// ValidateDKGParameters validates DKG fault constraints:
// n > 3*t (Byzantine Consensus), n - 2*t >= k (AVSS reconstruction), k >= t + 1 (Fault tolerance)
func ValidateDKGParameters(n, k, t int) error {
	if n <= 0 || k <= 0 || t <= 0 {
		return fmt.Errorf("invalid DKG parameters: n, k, and t must be positive integers (got n=%d, k=%d, t=%d)", n, k, t)
	}
	if n <= 3*t {
		return fmt.Errorf("invalid DKG parameters: consensus requires n > 3t (got n=%d, t=%d, 3t=%d)", n, t, 3*t)
	}
	if n-2*t < k {
		return fmt.Errorf("invalid DKG parameters: reconstruction requires n - 2t >= k (got %d - 2*%d = %d < %d)", n, t, n-2*t, k)
	}
	if k < t+1 {
		return fmt.Errorf("invalid DKG parameters: threshold k must be at least t + 1 (got k=%d, t=%d)", k, t)
	}
	return nil
}

// handleStartDKG coordinates initialization of a Dealerless DKG across the committee nodes
func (s *Server) handleStartDKG(params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID   string   `json:"sessionId"`
		CommitteeID string   `json:"committeeId"`
		N           int      `json:"n"`
		K           int      `json:"k"`
		T           int      `json:"t"`
		Committee   []string `json:"committee"`
		WalletID    string   `json:"walletId"`
		KeyID       string   `json:"keyId"`
		UserID      string   `json:"userId"`
		Curve       string   `json:"curve"`
		ChainFamily string   `json:"chainFamily"`
	}
	if len(params) > 0 && json.Unmarshal(params, &req) != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
	}

	scope := walletDKGScope{
		user: req.UserID, wallet: req.WalletID, key: req.KeyID, session: req.SessionID,
		committee: req.CommitteeID, curve: req.Curve, chain: req.ChainFamily, epoch: 1,
	}
	walletBound := req.UserID != "" || req.WalletID != "" || req.KeyID != "" || req.ChainFamily != ""
	if walletBound {
		if err := s.verifyWalletDKGScope(token, "start_dkg", scope); err != nil {
			return nil, err
		}
	} else {
		if _, err := s.verifyDKGOperator(token); err != nil {
			return nil, err
		}
		if req.Curve != "" && req.Curve != "nist-p256" && req.Curve != "NIST P-256" {
			return nil, &JsonRpcErr{Code: -32602, Message: "Unbound DKG requires the NIST P-256 curve"}
		}
		req.Curve = "nist-p256"
	}

	committee := req.Committee
	if len(committee) == 0 {
		if walletBound {
			committee = walletCommitteeNodes(s.domain)
		} else if req.N != 5 {
			for id := range s.monitor.GetAuthorizedParticipants() {
				committee = append(committee, id)
			}
		}
		if len(committee) == 0 {
			for _, node := range s.registry.GetAllNodes() {
				committee = append(committee, node.NodeID)
			}
		}
	}

	normalized := make([]string, 0, len(committee))
	seen := make(map[string]bool, len(committee))
	for _, node := range committee {
		id, _ := membership.NormalizeNodeID(node)
		if id == "" || seen[id] {
			return nil, &JsonRpcErr{Code: -32602, Message: "DKG committee must contain distinct node identifiers"}
		}
		seen[id] = true
		normalized = append(normalized, id)
	}
	sort.Strings(normalized)
	if req.N != 0 && req.N != len(normalized) {
		return nil, &JsonRpcErr{Code: -32602, Message: "DKG committee size and n do not match"}
	}
	req.N = len(normalized)
	if req.K == 0 && req.T == 0 {
		switch req.N {
		case 5:
			req.K, req.T = 3, 1
		case 15:
			req.K, req.T = 5, 4
		}
	}
	if err := ValidateDKGParameters(req.N, req.K, req.T); err != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: err.Error()}
	}
	if walletBound && (req.K != 3 || req.T != 1 || !slices.Equal(normalized, walletCommitteeNodes(s.domain))) {
		return nil, &JsonRpcErr{Code: -32602, Message: "Wallet DKG requires this domain's canonical 3-of-5 committee"}
	}
	if req.SessionID == "" {
		req.SessionID = fmt.Sprintf("dkg-%s-%d", strings.ToLower(string(s.domain)), time.Now().UnixNano())
	}
	if req.CommitteeID == "" {
		req.CommitteeID = fmt.Sprintf("comm-%d", req.N)
	}
	if !walletIdentifier.MatchString(req.SessionID) || !walletIdentifier.MatchString(req.CommitteeID) {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid DKG session or committee identifier"}
	}

	startResponse := func(state string) map[string]interface{} {
		return map[string]interface{}{
			"success": true, "sessionId": req.SessionID, "committeeId": req.CommitteeID,
			"state": state, "n": req.N, "k": req.K, "t": req.T, "committee": normalized,
		}
	}

	s.dkgStartMu.Lock()
	defer s.dkgStartMu.Unlock()
	s.avssMu.RLock()
	existing := s.dkgSessions[req.SessionID]
	if existing != nil {
		same := existing.scope == scope && existing.Curve == req.Curve && existing.CommitteeID == req.CommitteeID &&
			existing.K == req.K && existing.T == req.T && slices.Equal(existing.Committee, normalized)
		state := existing.State
		s.avssMu.RUnlock()
		if !same {
			return nil, &JsonRpcErr{Code: -32602, Message: "DKG session ID belongs to a different configuration"}
		}
		if !walletBound || state == "COMPLETED" {
			return startResponse(state), nil
		}
	} else {
		s.avssMu.RUnlock()
	}

	state := "CONTRIBUTIONS_STARTED"
	var started []string
	if walletBound {
		query := "?sessionId=" + req.SessionID + "&keyId=" + req.KeyID
		started = s.callDKGCommittee(normalized, func(endpoint string) bool {
			var status struct {
				State string `json:"state"`
			}
			return s.getNodeJSON(endpoint+"/node/dkg/status"+query, &status) == nil && status.State == "COMPLETED"
		})
		if len(started) >= req.K {
			state = "COMPLETED"
		}
	}

	initPayload := map[string]interface{}{
		"sessionId": req.SessionID, "committeeId": req.CommitteeID, "committee": normalized,
		"n": req.N, "k": req.K, "t": req.T, "walletId": req.WalletID, "keyId": req.KeyID,
		"userId": req.UserID, "curve": req.Curve, "chainFamily": req.ChainFamily,
	}
	if state != "COMPLETED" {
		nodes := s.callDKGCommittee(normalized, func(endpoint string) bool {
			return s.postNodeJSONWithAuth(endpoint+"/node/dkg/init", initPayload, nil, token) == nil
		})
		if len(nodes) < req.N-req.T {
			return nil, &JsonRpcErr{Code: -32000, Message: "Could not initialize enough DKG committee nodes"}
		}
		started = s.callDKGCommittee(nodes, func(endpoint string) bool {
			return s.postNodeJSONWithAuth(endpoint+"/node/dkg/start", map[string]string{"sessionId": req.SessionID}, nil, token) == nil
		})
		if len(started) < req.N-req.T {
			return nil, &JsonRpcErr{Code: -32000, Message: "Could not start enough DKG committee nodes"}
		}
	}

	participants := make(map[string]*DKGParticipantSummary, req.N)
	for index, id := range normalized {
		participants[id] = &DKGParticipantSummary{
			NodeID: id, NodeIndex: index + 1, ContributionDealt: slices.Contains(started, id),
			Status: "CONTRIBUTIONS_STARTED",
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	meta := &DKGSessionMeta{
		SessionID: req.SessionID, CommitteeID: req.CommitteeID, Epoch: 1, N: req.N, K: req.K, T: req.T,
		State: state, Committee: normalized, Curve: req.Curve, Participants: participants,
		CreatedAt: now, UpdatedAt: now, scope: scope,
	}
	s.avssMu.Lock()
	if s.dkgSessions == nil {
		s.dkgSessions = make(map[string]*DKGSessionMeta)
	}
	s.dkgSessions[req.SessionID] = meta
	s.avssMu.Unlock()
	return startResponse(meta.State), nil
}

func (s *Server) callDKGCommittee(nodes []string, call func(string) bool) []string {
	var wg sync.WaitGroup
	success := make(chan string, len(nodes))
	for _, node := range nodes {
		endpoint := s.getNodeEndpoint(node)
		if endpoint == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if call(endpoint) {
				success <- node
			}
		}()
	}
	wg.Wait()
	close(success)
	completed := make([]string, 0, len(nodes))
	for node := range success {
		completed = append(completed, node)
	}
	return completed
}

func (s *Server) handleGetDKGStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID string `json:"sessionId"`
	}
	if len(params) > 0 && json.Unmarshal(params, &req) != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
	}

	s.avssMu.RLock()
	var stored *DKGSessionMeta
	if req.SessionID != "" {
		stored = s.dkgSessions[req.SessionID]
	} else {
		for _, candidate := range s.dkgSessions {
			if candidate.scope.user == "" {
				stored = candidate
				break
			}
		}
	}
	if stored == nil {
		s.avssMu.RUnlock()
		return map[string]interface{}{"status": "NO_ACTIVE_DKG_SESSION"}, nil
	}
	meta := *stored
	meta.Participants = make(map[string]*DKGParticipantSummary, len(stored.Participants))
	for id, participant := range stored.Participants {
		copy := *participant
		meta.Participants[id] = &copy
	}
	s.avssMu.RUnlock()

	type nodeView struct {
		State                  string   `json:"state"`
		MasterSigningPublicKey string   `json:"masterSigningPublicKey"`
		MasterSecretCommitment string   `json:"masterSecretCommitment"`
		MasterPublicKey        string   `json:"masterPublicKey"`
		QualifiedSet           []string `json:"qualifiedSet"`
	}
	type diagnostics struct {
		publicKey, signingKey, commitment string
	}
	votes := make(map[diagnostics]int)
	views := make(chan nodeView, len(meta.Committee))
	query := "?sessionId=" + meta.SessionID
	if meta.scope.key != "" {
		query += "&keyId=" + meta.scope.key
	}
	finished := s.callDKGCommittee(meta.Committee, func(endpoint string) bool {
		var view nodeView
		err := s.getNodeJSON(endpoint+"/node/dkg/status"+query, &view)
		if err != nil || view.State != "COMPLETED" {
			return false
		}
		views <- view
		return true
	})
	close(views)
	for _, id := range finished {
		if participant := meta.Participants[id]; participant != nil {
			participant.Status = "COMPLETED"
		}
	}
	for view := range views {
		// Wallet nodes may load authenticated commitments from their vault after restart.
		if meta.scope.user != "" {
			continue
		}
		key := diagnostics{view.MasterPublicKey, view.MasterSigningPublicKey, view.MasterSecretCommitment}
		votes[key]++
		if votes[key] >= meta.N-meta.T && view.MasterPublicKey != "" {
			meta.State = "COMPLETED"
			meta.MasterPublicKey = view.MasterPublicKey
			meta.MasterSigningPublicKey = view.MasterSigningPublicKey
			meta.MasterSecretCommitment = view.MasterSecretCommitment
			meta.QualifiedSet = view.QualifiedSet
		}
	}
	if meta.scope.user != "" {
		meta.State = "CONTRIBUTIONS_STARTED"
		if len(finished) >= meta.K {
			meta.State = "COMPLETED"
		}
		// The public key for a wallet is always obtained through the scoped derivation RPC.
	}
	s.avssMu.Lock()
	if original := s.dkgSessions[meta.SessionID]; original == stored {
		if original.State != "COMPLETED" || meta.State == "COMPLETED" {
			s.dkgSessions[meta.SessionID] = &meta
		}
	}
	s.avssMu.Unlock()

	return map[string]interface{}{
		"sessionId": meta.SessionID, "committeeId": meta.CommitteeID, "epoch": meta.Epoch,
		"n": meta.N, "k": meta.K, "t": meta.T, "state": meta.State, "committee": meta.Committee,
		"qualifiedSet": meta.QualifiedSet, "masterSigningPublicKey": meta.MasterSigningPublicKey,
		"masterSecretCommitment": meta.MasterSecretCommitment, "masterPublicKey": meta.MasterPublicKey,
		"curve": meta.Curve, "completedNodes": len(finished), "totalNodes": meta.N, "participants": meta.Participants,
	}, nil
}

// handleGetDKGParticipants returns participant progress for a DKG session
func (s *Server) handleGetDKGParticipants(params json.RawMessage) (interface{}, *JsonRpcErr) {
	status, err := s.handleGetDKGStatus(params)
	if err != nil {
		return nil, err
	}
	m, ok := status.(map[string]interface{})
	if !ok {
		return nil, &JsonRpcErr{Code: -32000, Message: "failed to retrieve DKG participants"}
	}
	return map[string]interface{}{
		"sessionId":    m["sessionId"],
		"committeeId":  m["committeeId"],
		"participants": m["participants"],
		"qualifiedSet": m["qualifiedSet"],
	}, nil
}

// handleGetDKGPublicKey returns the agreed master public key
func (s *Server) handleGetDKGPublicKey(params json.RawMessage) (interface{}, *JsonRpcErr) {
	status, err := s.handleGetDKGStatus(params)
	if err != nil {
		return nil, err
	}
	m, ok := status.(map[string]interface{})
	if !ok {
		return nil, &JsonRpcErr{Code: -32000, Message: "failed to retrieve DKG public key"}
	}
	return map[string]interface{}{
		"sessionId":       m["sessionId"],
		"committeeId":     m["committeeId"],
		"masterPublicKey": m["masterPublicKey"],
		"curve":           m["curve"],
		"threshold":       m["k"],
		"state":           m["state"],
	}, nil
}

// handleGetDKGVerificationStatus returns public verification status across participants
func (s *Server) handleGetDKGVerificationStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	status, err := s.handleGetDKGStatus(params)
	if err != nil {
		return nil, err
	}
	m, ok := status.(map[string]interface{})
	if !ok {
		return nil, &JsonRpcErr{Code: -32000, Message: "failed to retrieve DKG verification status"}
	}
	allVerified := (m["state"] == "COMPLETED")
	return map[string]interface{}{
		"sessionId":       m["sessionId"],
		"committeeId":     m["committeeId"],
		"verified":        allVerified,
		"state":           m["state"],
		"masterPublicKey": m["masterPublicKey"],
		"qualifiedSet":    m["qualifiedSet"],
		"completedNodes":  m["completedNodes"],
		"totalNodes":      m["totalNodes"],
	}, nil
}

type DerivePublicKeyParams struct {
	WalletID     string `json:"walletId"`
	UserID       string `json:"userId"`
	KeyID        string `json:"keyId"`
	DKGSessionID string `json:"dkgSessionId"`
	CommitteeID  string `json:"committeeId"`
	Curve        string `json:"curve"`
	ChainFamily  string `json:"chainFamily"`
	Epoch        uint64 `json:"epoch"`
}

// handleDerivePublicKey reconstructs only the public point for an exact wallet key and epoch.
func (s *Server) handleDerivePublicKey(params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	var req DerivePublicKeyParams
	if json.Unmarshal(params, &req) != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
	}
	scope := walletDKGScope{
		user: req.UserID, wallet: req.WalletID, key: req.KeyID, session: req.DKGSessionID,
		committee: req.CommitteeID, curve: req.Curve, chain: req.ChainFamily, epoch: req.Epoch,
	}
	if err := s.verifyWalletDKGScope(token, "derive_public_key", scope); err != nil {
		return nil, err
	}
	s.avssMu.RLock()
	meta := s.dkgSessions[scope.session]
	mismatch := meta != nil && meta.scope != scope
	s.avssMu.RUnlock()
	if mismatch {
		return nil, &JsonRpcErr{Code: -32001, Message: "Wallet DKG session scope mismatch"}
	}
	// Domain membership and vault-authenticated scopes remain valid across coordinator restarts.
	committee := walletCommitteeNodes(s.domain)
	payload := map[string]interface{}{
		"userId": scope.user, "walletId": scope.wallet, "keyId": scope.key, "sessionId": scope.session,
		"committeeId": scope.committee, "curve": scope.curve, "chainFamily": scope.chain, "epoch": scope.epoch,
	}
	var wg sync.WaitGroup
	responses := make(chan walletPublicContribution, len(committee))
	for index, node := range committee {
		endpoint := s.getNodeEndpoint(node)
		if endpoint == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var response struct {
				NodeID                     string `json:"nodeId"`
				NodeIndex                  int    `json:"nodeIndex"`
				Epoch                      uint64 `json:"epoch"`
				PublicPoint                string `json:"publicPoint"`
				MasterSigningPublicKeyHash string `json:"masterSigningPublicKeyHash"`
			}
			err := s.postNodeJSONWithAuth(endpoint+"/node/dkg/share-contribution", payload, &response, token)
			if err != nil || response.NodeID != node || response.NodeIndex != index+1 || response.Epoch != scope.epoch {
				return
			}
			digest, err := hex.DecodeString(response.MasterSigningPublicKeyHash)
			if err != nil || len(digest) != sha256.Size {
				return
			}
			point, err := decodeWalletPublicPoint(response.PublicPoint, scope.curve)
			if err != nil {
				return
			}
			responses <- walletPublicContribution{response.NodeIndex, point, [sha256.Size]byte(digest)}
		}()
	}
	wg.Wait()
	close(responses)
	var contributions []walletPublicContribution
	for response := range responses {
		contributions = append(contributions, response)
	}
	publicKey, _, err := reconstructVerifiedWalletKey(contributions, scope.curve)
	if err != nil {
		return nil, &JsonRpcErr{Code: -32000, Message: err.Error()}
	}
	return map[string]interface{}{
		"success": true, "walletId": scope.wallet, "keyId": scope.key, "sessionId": scope.session,
		"committeeId": scope.committee, "epoch": scope.epoch, "curve": scope.curve,
		"threshold": 3, "masterPublicKey": publicKey,
	}, nil
}

type walletPublicContribution struct {
	index  int
	point  *CurvePoint
	master [sha256.Size]byte
}

func reconstructVerifiedWalletKey(contributions []walletPublicContribution, curve string) (string, *CurvePoint, error) {
	// Each matching commitment is attested by at least three distinct registered members.
	// Try each possible triple so a faulty response cannot displace other usable contributions.
	for i, first := range contributions {
		for j := i + 1; j < len(contributions); j++ {
			second := contributions[j]
			if first.master != second.master || first.index == second.index {
				continue
			}
			for _, third := range contributions[j+1:] {
				if first.master != third.master || first.index == third.index || second.index == third.index {
					continue
				}
				point, err := InterpolatePublicContributionsAtZeroForCurve(
					[]int{first.index, second.index, third.index},
					[]*CurvePoint{first.point, second.point, third.point},
					curve,
				)
				if err != nil || !validWalletPublicPoint(point, curve) {
					continue
				}
				key := fmt.Sprintf("04%064x%064x", point.X, point.Y)
				encoded, err := hex.DecodeString(key)
				if err == nil && sha256.Sum256(encoded) == first.master {
					return key, point, nil
				}
			}
		}
	}
	return "", nil, fmt.Errorf("no threshold of wallet shares matched the verified DKG public key commitment")
}

func decodeWalletPublicPoint(raw, curve string) (*CurvePoint, error) {
	if len(raw) != 130 || !strings.HasPrefix(raw, "04") {
		return nil, fmt.Errorf("invalid wallet public point encoding")
	}
	encoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	point := &CurvePoint{X: new(big.Int).SetBytes(encoded[1:33]), Y: new(big.Int).SetBytes(encoded[33:])}
	if !validWalletPublicPoint(point, curve) {
		return nil, fmt.Errorf("invalid wallet public point for %s", curve)
	}
	return point, nil
}

func validWalletPublicPoint(point *CurvePoint, curve string) bool {
	if point == nil || point.X == nil || point.Y == nil || point.X.Sign() < 0 || point.Y.Sign() < 0 {
		return false
	}
	x, y := point.X, point.Y
	x2 := new(big.Int).Mul(x, x)
	y2 := new(big.Int).Mul(y, y)
	switch curve {
	case "secp256k1":
		if x.Cmp(Secp256k1P) >= 0 || y.Cmp(Secp256k1P) >= 0 {
			return false
		}
		rhs := new(big.Int).Mul(x2, x)
		rhs.Add(rhs, big.NewInt(7)).Mod(rhs, Secp256k1P)
		return y2.Mod(y2, Secp256k1P).Cmp(rhs) == 0
	case "ed25519":
		if x.Cmp(Ed25519P) >= 0 || y.Cmp(Ed25519P) >= 0 || (x.Sign() == 0 && y.Cmp(big.NewInt(1)) == 0) {
			return false
		}
		lhs := new(big.Int).Sub(y2, x2)
		lhs.Mod(lhs, Ed25519P)
		rhs := new(big.Int).Mul(x2, y2)
		rhs.Mul(rhs, Ed25519D).Add(rhs, big.NewInt(1)).Mod(rhs, Ed25519P)
		if lhs.Cmp(rhs) != 0 {
			return false
		}
		orderX, orderY := Ed25519ScalarMult(x, y, Ed25519L)
		return orderX.Sign() == 0 && orderY.Cmp(big.NewInt(1)) == 0
	}
	return false
}
