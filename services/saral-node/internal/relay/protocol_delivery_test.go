package relay

import (
	"fmt"
	"testing"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/crypto"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/membership"
)

func TestProtocolRelayWaitsForAcceptanceAndRequiresDestinationEncryption(t *testing.T) {
	const source, target = "saral-foundation-1", "saral-foundation-2"
	sender, err := identity.LoadOrGenerateIdentity(t.TempDir(), source, "FOUNDATION", 1)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	destination, err := identity.LoadOrGenerateIdentity(dir, target, "FOUNDATION", 2)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRelayRouter(destination, "FOUNDATION", nil, "", dir)
	defer router.Stop()
	router.RegisterTrustedParticipant(membership.ParticipantEntry{
		NodeID: source, Domain: "FOUNDATION", PublicKeyHex: sender.Identity.PublicKeyHex,
	})

	p := map[string]any{"sessionId": "wallet-session"}
	if _, err := router.Send(RelaySendRequest{TargetNode: source, Type: "AVSS_SEND", Payload: p}); err == nil {
		t.Fatal("protocol traffic was sent without a trusted destination encryption key")
	}

	var accepted int
	router.RegisterMessageHandler("AVSS_SEND", func(*RelayMessage) error {
		accepted++
		if accepted == 1 {
			return fmt.Errorf("session unavailable")
		}
		return nil
	})
	newMessage := func(encrypted string) RelayMessage {
		m := RelayMessage{
			MessageID: "protocol-message", SourceNode: source, SourceDomain: "FOUNDATION",
			TargetNode: target, TargetDomain: "FOUNDATION", PublicKeyHex: sender.Identity.PublicKeyHex,
			Type: "AVSS_SEND", EncryptedPayload: encrypted, Timestamp: time.Now().UnixMilli(),
			ExpiresAt: time.Now().Add(30 * time.Second).UnixMilli(), HopLimit: 5,
		}
		m.SignatureHex = sender.Sign(CanonicalMessagePayload(&m))
		return m
	}
	clusterPayload, err := crypto.EncryptPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	if ack, err := router.HandleIncomingRelay(newMessage(clusterPayload)); err != nil || ack.Status != StateFailed || accepted != 0 {
		t.Fatalf("cluster encryption reached protocol processing: %+v, %v", ack, err)
	}

	privatePayload, err := crypto.EncryptForDestination(destination.GetEncryptionPublicKeyHex(), p)
	if err != nil {
		t.Fatal(err)
	}
	message := newMessage(privatePayload)
	if ack, err := router.HandleIncomingRelay(message); err != nil || ack.Status != StateFailed {
		t.Fatalf("message was acknowledged before acceptance: %+v, %v", ack, err)
	}
	for range 2 {
		if ack, err := router.HandleIncomingRelay(message); err != nil || ack.Status != StateAcknowledged {
			t.Fatalf("accepted protocol retry was dropped: %+v, %v", ack, err)
		}
	}
	if accepted != 2 {
		t.Fatalf("expected one rejected attempt and one accepted retry, got %d handler calls", accepted)
	}
}
