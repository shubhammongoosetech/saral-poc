package dkg_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/dkg"
	"github.com/saral-protocol/saral-poc/services/saral-node/proactive"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

type walletRelay struct {
	dkg         map[string]*dkg.Engine
	avss        map[string]*avss.Engine
	unavailable string
}

func (r *walletRelay) SendToNode(node, _ string, kind string, payload []byte) error {
	if node == r.unavailable {
		return fmt.Errorf("node unavailable")
	}
	switch kind {
	case avss.MessageTypeSend:
		return deliverWalletMessage(payload, r.avss[node].HandleSendMessage)
	case avss.MessageTypeEcho:
		return deliverWalletMessage(payload, r.avss[node].HandleEchoMessage)
	case avss.MessageTypeReady:
		return deliverWalletMessage(payload, r.avss[node].HandleReadyMessage)
	case dkg.MessageTypeDKGContribution:
		return deliverWalletMessage(payload, r.dkg[node].HandleDKGContribution)
	case dkg.MessageTypeWalletAgreement:
		return deliverWalletMessage(payload, r.dkg[node].HandleWalletAgreement)
	case proactive.MessageTypeAgreementPropose:
		return deliverWalletMessage(payload, r.dkg[node].HandleAgreementPropose)
	case proactive.MessageTypeAgreementEcho:
		return deliverWalletMessage(payload, r.dkg[node].HandleAgreementEcho)
	case proactive.MessageTypeAgreementReady:
		return deliverWalletMessage(payload, r.dkg[node].HandleAgreementReady)
	}
	return nil
}

func deliverWalletMessage[T any](payload []byte, handler func(*T) error) error {
	var message T
	if err := json.Unmarshal(payload, &message); err != nil {
		return err
	}
	return handler(&message)
}

func TestWalletDKGRestoresTheSameKeyAcrossQuorums(t *testing.T) {
	for _, tc := range []struct {
		curve   cryptography.Curve
		chain   string
		domain  string
		offline bool
	}{
		{cryptography.CurveSecp256k1, "mst", "foundation", false},
		{cryptography.CurveEd25519, "solana", "public", false},
		{cryptography.CurveSecp256k1, "bitcoin", "private", true},
	} {
		t.Run(tc.domain+"/"+string(tc.curve), func(t *testing.T) {
			const sessionID, keyID = "wallet-dkg", "wallet-key"
			committeeID := "committee-" + tc.domain
			domain := strings.ToUpper(tc.domain)
			committee := make([]string, 5)
			for i := range committee {
				committee[i] = fmt.Sprintf("saral-%s-%d", tc.domain, i+1)
			}
			network := &walletRelay{dkg: map[string]*dkg.Engine{}, avss: map[string]*avss.Engine{}}
			live := committee
			if tc.offline {
				live = committee[1:]
				network.unavailable = committee[0]
			}
			dir := t.TempDir()
			stores := make(map[string]*vault.ShareStore)
			signing := make(map[string]ed25519.PrivateKey)
			trusted := make(map[string]string)
			for _, id := range committee {
				public, private, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
				signing[id], trusted[id] = private, hex.EncodeToString(public)
			}
			for _, id := range committee {
				store, err := vault.NewShareStore(filepath.Join(dir, id), []byte(id))
				if err != nil {
					t.Fatal(err)
				}
				stores[id] = store
				a := avss.NewEngine(id, domain, filepath.Join(dir, id), store, network)
				e := dkg.NewEngine(id, domain, filepath.Join(dir, id), store, a, network)
				e.ConfigureWalletAgreement(
					func(payload []byte) string { return hex.EncodeToString(ed25519.Sign(signing[id], payload)) },
					func(peer string) string { return trusted[peer] },
				)
				a.AddCompletionListener(e.OnAVSSSubprotocolCompleted)
				network.avss[id] = a
				network.dkg[id] = e
				if _, err := e.CreateSessionWithBinding(sessionID, committeeID, "wallet", keyID, "user", string(tc.curve), tc.chain, 5, 3, 1, committee); err != nil {
					t.Fatal(err)
				}
			}
			errs := make(chan error, len(live))
			for _, id := range live {
				go func() { errs <- network.dkg[id].StartContribution(sessionID) }()
			}
			for range live {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.Now().Add(15 * time.Second)
			for {
				ready := true
				for _, id := range live {
					ready = ready && network.dkg[id].HasPersistedWalletShare(sessionID, keyID)
				}
				if ready {
					break
				}
				if time.Now().After(deadline) {
					for _, id := range live {
						session, _ := network.dkg[id].GetSession(sessionID)
						t.Logf("%s: %s", id, session.GetPublicView().State)
					}
					t.Fatal("wallet DKG did not persist all online contributions")
				}
				time.Sleep(25 * time.Millisecond)
			}

			points := make(map[int]*cryptography.CurvePoint)
			hash := ""
			for idx, id := range committee {
				if id == network.unavailable {
					continue
				}
				restarted := dkg.NewEngine(id, domain, "", stores[id], nil, nil)
				pointHex, index, epoch, _, meta, err := restarted.GetPublicShareContribution(keyID, sessionID, committeeID, string(tc.curve), 1)
				if err != nil || index != idx+1 || epoch != 1 {
					t.Fatalf("restarted %s lost its contribution: %v", id, err)
				}
				if hash == "" {
					hash = meta.MasterSigningPublicKeyHash
				}
				if meta.MasterSigningPublicKeyHash != hash {
					t.Fatal("node master key digests differ")
				}
				points[index], err = tc.curve.ParsePoint(pointHex)
				if err != nil {
					t.Fatal(err)
				}
				sameSession, err := restarted.CreateSessionWithBinding(sessionID, committeeID, "wallet", keyID, "user", string(tc.curve), tc.chain, 5, 3, 1, committee)
				if err != nil || sameSession.GetPublicView().State != dkg.StateCompleted {
					t.Fatalf("same DKG start did not reuse vault state: %v", err)
				}
				if _, err := restarted.CreateSessionWithBinding(sessionID, committeeID, "wallet", keyID, "other-user", string(tc.curve), tc.chain, 5, 3, 1, committee); err == nil {
					t.Fatal("same DKG session accepted different owner")
				}
				if _, _, _, _, _, err := restarted.GetPublicShareContribution(keyID, "other-session", committeeID, string(tc.curve), 1); err == nil {
					t.Fatal("wallet contribution accepted a different session")
				}
			}
			firstQuorum := []int{1, 2, 3}
			if tc.offline {
				firstQuorum = []int{2, 3, 4}
			}
			for _, indices := range [][]int{firstQuorum, {2, 4, 5}} {
				xs := make([]*cryptography.FieldElement, len(indices))
				for i, index := range indices {
					xs[i] = tc.curve.Scalar(int64(index))
				}
				combined := tc.curve.Identity()
				for i, index := range indices {
					weight, err := cryptography.LagrangeCoefficient(tc.curve.Scalar(0), xs[i], xs)
					if err != nil {
						t.Fatal(err)
					}
					combined = combined.Add(points[index].ScalarMult(weight))
				}
				digest := sha256.Sum256(combined.Bytes())
				if hex.EncodeToString(digest[:]) != hash {
					t.Fatalf("quorum %v returned a different wallet public key", indices)
				}
			}
		})
	}
}
