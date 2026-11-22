package dkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

type storedWalletDealer struct {
	Secret string                       `json:"secret"`
	Blind  string                       `json:"blind"`
	Sends  map[string]*avss.SendMessage `json:"sends"`
}

func (s *Session) prepareLocalDealer() (*avss.DealerPackage, error) {
	bound := s.UserBindingID != ""
	if bound {
		existing, err := s.loadWalletDealer()
		if err != nil || existing != nil {
			return existing, err
		}
	}
	secret, err := s.Curve.RandomScalar()
	if err != nil {
		return nil, err
	}
	blind, err := s.Curve.RandomScalar()
	if err != nil {
		return nil, err
	}
	subSessionID := fmt.Sprintf("dkg-%s-contrib-%s", s.SessionID, s.SelfID)
	pkg, err := avss.GenerateDealerSharing(subSessionID, s.CommitteeID, s.SelfID, s.Epoch, s.Committee, s.K, secret, blind)
	if err != nil {
		return nil, err
	}
	if bound {
		if err := s.saveWalletDealer(pkg); err != nil {
			return nil, err
		}
	}
	return pkg, nil
}

func (s *Session) walletScope() string {
	encoded, _ := json.Marshal([]any{
		s.SessionID, s.CommitteeID, s.WalletID, s.KeyID, s.UserBindingID, s.ChainFamily,
		s.Curve, s.Epoch, s.K, s.T, s.Committee,
	})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (s *Session) reserveWalletSession() error {
	keyDigest := sha256.Sum256([]byte(s.KeyID))
	recordID := hex.EncodeToString(keyDigest[:])
	scope := s.walletScope()
	data, err := s.ShareStore.LoadProtocolState(recordID, "key-binding")
	if err == nil {
		if string(data) != scope {
			return fmt.Errorf("wallet key already belongs to another session")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.ShareStore.SaveProtocolState(recordID, "key-binding", []byte(scope))
}

func (s *Session) activateWalletShare(meta vault.ShareRecordMetadata, share, blind *cryptography.FieldElement) error {
	if err := s.ShareStore.DeleteProtocolState(s.walletScope(), "dealer"); err != nil {
		return err
	}
	meta.State = "ACTIVE"
	return s.ShareStore.SaveShare(meta, share, blind)
}

func (s *Session) saveWalletAnnouncement(message DKGContributionMessage) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return s.ShareStore.SaveProtocolState(s.walletScope(), "dealer-announcement", data)
}

func (s *Session) loadWalletAnnouncement() (DKGContributionMessage, error) {
	var message DKGContributionMessage
	data, err := s.ShareStore.LoadProtocolState(s.walletScope(), "dealer-announcement")
	if errors.Is(err, os.ErrNotExist) {
		return message, nil
	}
	if err == nil {
		err = json.Unmarshal(data, &message)
	}
	return message, err
}

func (s *Session) loadWalletDealer() (*avss.DealerPackage, error) {
	data, err := s.ShareStore.LoadProtocolState(s.walletScope(), "dealer")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var record storedWalletDealer
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	secret, err := s.Curve.ParseScalar(record.Secret)
	if err != nil {
		return nil, err
	}
	blind, err := s.Curve.ParseScalar(record.Blind)
	if err != nil {
		secret.Zero()
		return nil, err
	}
	local := record.Sends[s.SelfID]
	if local == nil || len(record.Sends) != s.N {
		return nil, fmt.Errorf("invalid dealer checkpoint recipients")
	}
	matrix, err := avss.ParseCommitmentMatrixForCurve(local.Commitments, s.Curve)
	if err != nil {
		return nil, err
	}
	if !matrix.SecretCommitment().Equal(cryptography.PedersenCommitment(secret, blind)) {
		return nil, fmt.Errorf("dealer checkpoint does not match its commitment")
	}
	expectedID := fmt.Sprintf("dkg-%s-contrib-%s", s.SessionID, s.SelfID)
	commitmentsHash := avss.HashCommitments(local.Commitments)
	for _, id := range s.Committee {
		send := record.Sends[id]
		if send == nil || send.SessionID != expectedID || send.CommitteeID != s.CommitteeID ||
			send.Epoch != s.Epoch || send.DealerID != s.SelfID || send.RecipientID != id ||
			avss.HashCommitments(send.Commitments) != commitmentsHash {
			return nil, fmt.Errorf("dealer checkpoint metadata mismatch")
		}
	}
	return &avss.DealerPackage{
		SessionID: local.SessionID, Secret: secret, BlindSecret: blind, CommitmentMatrix: matrix, SendMessages: record.Sends,
	}, nil
}

func (s *Session) saveWalletDealer(p *avss.DealerPackage) error {
	data, err := json.Marshal(storedWalletDealer{p.Secret.Hex(), p.BlindSecret.Hex(), p.SendMessages})
	if err != nil {
		return err
	}
	defer clear(data)
	return s.ShareStore.SaveProtocolState(s.walletScope(), "dealer", data)
}
