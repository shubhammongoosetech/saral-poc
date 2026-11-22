package dkg

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

func TestWalletDKGCheckpointPreservesDealerAndPreparedValue(t *testing.T) {
	store, err := vault.NewShareStore(t.TempDir(), []byte("wallet-restart-test"))
	if err != nil {
		t.Fatal(err)
	}
	committee := []string{"saral-foundation-1", "saral-foundation-2", "saral-foundation-3", "saral-foundation-4", "saral-foundation-5"}
	newSession := func() *Session {
		s, err := NewSession("session", "committee-foundation", committee[2], 3, committee, 5, 3, 1, store)
		if err != nil {
			t.Fatal(err)
		}
		s.KeyID = "key"
		s.WalletID = "wallet"
		s.UserBindingID = "user"
		s.ChainFamily = "mst"
		s.Curve = cryptography.CurveSecp256k1
		return s
	}

	initial := newSession()
	first, err := initial.StartContribution()
	if err != nil {
		t.Fatal(err)
	}
	restarted := newSession()
	replayed, err := restarted.StartContribution()
	if err != nil {
		t.Fatal(err)
	}
	aBytes, _ := json.Marshal(first.SendMessages)
	bBytes, _ := json.Marshal(replayed.SendMessages)
	if string(aBytes) != string(bBytes) {
		t.Fatal("an interrupted dealer retry generated different shares")
	}

	keys := make(map[string]ed25519.PrivateKey)
	publics := make(map[string]string)
	for _, id := range committee {
		public, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keys[id], publics[id] = private, hex.EncodeToString(public)
	}
	sign := func(id string, payload []byte) string {
		return hex.EncodeToString(ed25519.Sign(keys[id], payload))
	}
	newAgreement := func(s *Session) *walletAgreement {
		a, err := newWalletAgreement(s, func(payload []byte) string { return sign(s.SelfID, payload) },
			func(nodeID string) string { return publics[nodeID] })
		if err != nil {
			t.Fatal(err)
		}
		a.begin()
		return a
	}
	a := newAgreement(initial)
	vote := func(id string, v WalletVote) WalletVote {
		v.Scope, v.Sender = a.scope, id
		v.Signature = sign(id, walletVotePayload(v))
		return v
	}
	makeValue := func(dealers []string) walletValue {
		var value walletValue
		for _, id := range dealers {
			digest := walletAgreementDigest(id)
			cert := walletDealerCertificate{Dealer: id, Digest: digest}
			for _, signer := range committee[:a.quorum] {
				cert.Votes = append(cert.Votes, vote(signer, WalletVote{Phase: walletDealerReady, Dealer: id, Digest: digest}))
			}
			value = append(value, cert)
		}
		return value
	}
	newProposal := func(view uint64, value walletValue, changes []WalletVote) *WalletProposal {
		leader := a.leader(view)
		p := WalletProposal{Scope: a.scope, View: view, Leader: leader, Value: value, NewView: changes}
		p.Signature = sign(leader, walletProposalPayload(p))
		return &p
	}
	deliver := func(agreement *walletAgreement, message WalletAgreementMessage) {
		if err := agreement.receive(&message); err != nil {
			t.Fatal(err)
		}
	}

	firstValue, conflictingValue := makeValue(committee[:2]), makeValue(committee[2:4])
	deliver(a, WalletAgreementMessage{Proposal: newProposal(0, firstValue, nil)})
	for _, id := range committee[:a.quorum] {
		prepare := vote(id, WalletVote{Phase: walletPrepare, Digest: valueDigest(firstValue)})
		deliver(a, WalletAgreementMessage{Vote: &prepare})
	}
	if a.state.Prepared == nil {
		t.Fatal("expected a prepared quorum")
	}

	restored := newAgreement(restarted)
	deliver(restored, WalletAgreementMessage{Proposal: newProposal(0, conflictingValue, nil)})
	if restored.state.Prepared == nil || restored.state.Own[walletPrepare].Digest != valueDigest(firstValue) {
		t.Fatal("restart lost the original agreement lock")
	}
	changes := make([]WalletVote, 0, a.quorum)
	for _, id := range committee[:a.quorum] {
		change := WalletVote{Phase: walletNewView, View: 1}
		if id == initial.SelfID {
			change.Prepared = a.state.Prepared
		}
		changes = append(changes, vote(id, change))
	}
	if err := restored.receive(&WalletAgreementMessage{Proposal: newProposal(1, conflictingValue, changes)}); err == nil {
		t.Fatal("replacement leader overrode a prepared committee value")
	}
	deliver(restored, WalletAgreementMessage{Proposal: newProposal(1, firstValue, changes)})
	if restored.state.View != 1 || restored.state.Own[walletPrepare].Digest != valueDigest(firstValue) {
		t.Fatal("replacement leader could not progress the certified value")
	}

	meta := vault.ShareRecordMetadata{
		WalletID: initial.WalletID, KeyID: initial.KeyID, UserBindingID: initial.UserBindingID,
		DKGSessionID: initial.SessionID, CommitteeID: initial.CommitteeID, NodeID: initial.SelfID,
		NodeIndex: initial.SelfIndex, Epoch: initial.Epoch, Curve: string(initial.Curve),
		ChainFamily: initial.ChainFamily, Threshold: initial.K, State: "STAGED", RecordVersion: 2,
		MasterSigningPublicKeyHash: walletAgreementDigest("key"),
	}
	share, blind := initial.Curve.Scalar(17), initial.Curve.Scalar(22)
	if err := store.SaveShare(meta, share, blind); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(initial.SelfID, "FOUNDATION", "", store, nil, nil)
	if engine.HasPersistedWalletShare(initial.SessionID, initial.KeyID) {
		t.Fatal("staged share was published before deleting the dealer checkpoint")
	}
	session, err := engine.CreateSessionWithBinding(initial.SessionID, initial.CommitteeID, initial.WalletID, initial.KeyID,
		initial.UserBindingID, string(initial.Curve), initial.ChainFamily, 5, 3, 1, committee)
	if err != nil || session.GetPublicView().State != StateCompleted {
		t.Fatalf("restart did not resume staged wallet finalization: %v", err)
	}
	if dealer, err := restarted.loadWalletDealer(); err != nil || dealer != nil {
		t.Fatalf("final wallet kept the private dealer package: %v", err)
	}
	active, loadedShare, loadedBlind, err := store.LoadKeyShare(initial.KeyID, initial.Epoch)
	if err != nil || active.State != "ACTIVE" || !loadedShare.Equal(share) || !loadedBlind.Equal(blind) {
		t.Fatalf("finalization failed to keep the correct node share: %v", err)
	}
}
