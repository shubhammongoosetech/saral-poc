package rpc

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
)

var walletIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

type walletDKGScope struct {
	user, wallet, key, session, committee, curve, chain string
	epoch                                               uint64
}

func (scope walletDKGScope) valid() bool {
	if walletCommitteeDomain(scope.committee) == "" || scope.epoch != 1 {
		return false
	}
	for _, id := range []string{scope.user, scope.wallet, scope.key, scope.session} {
		if !walletIdentifier.MatchString(id) {
			return false
		}
	}
	switch scope.chain {
	case "mst", "bitcoin":
		return scope.curve == "secp256k1"
	case "solana":
		return scope.curve == "ed25519"
	}
	return false
}

func walletCommitteeDomain(committee string) membership.DomainType {
	switch committee {
	case "committee-foundation":
		return membership.DomainFoundation
	case "committee-public":
		return membership.DomainPublic
	case "committee-private":
		return membership.DomainPrivate
	default:
		return ""
	}
}

func walletCommitteeNodes(domain membership.DomainType) []string {
	nodes := make([]string, 5)
	for i := range nodes {
		nodes[i] = fmt.Sprintf("saral-%s-%d", strings.ToLower(string(domain)), i+1)
	}
	return nodes
}

func (s *Server) verifyDKGOperator(token string) (map[string]interface{}, *JsonRpcErr) {
	if s.verifierClient == nil || token == "" {
		return nil, &JsonRpcErr{Code: -32001, Message: "A verified operator token is required"}
	}
	result, err := s.verifierClient.VerifyTokenWithRole(token, "operator")
	if err != nil || result == nil || !result.Valid || result.Claims == nil {
		return nil, &JsonRpcErr{Code: -32001, Message: "Operator authorization rejected"}
	}
	return result.Claims, nil
}

func (s *Server) verifyWalletDKGScope(token, operation string, scope walletDKGScope) *JsonRpcErr {
	if !scope.valid() || s.domain != walletCommitteeDomain(scope.committee) {
		return &JsonRpcErr{Code: -32602, Message: "Invalid wallet DKG scope"}
	}
	claims, err := s.verifyDKGOperator(token)
	if err != nil {
		return err
	}
	if claims["mfaVerified"] != true || claims["policySatisfied"] != true || claims["epoch"] != float64(scope.epoch) {
		return &JsonRpcErr{Code: -32001, Message: "Wallet DKG token lacks the required session claims"}
	}
	for field, value := range map[string]string{
		"sub": scope.user, "userId": scope.user, "walletId": scope.wallet, "keyId": scope.key,
		"dkgSessionId": scope.session, "committeeId": scope.committee, "curve": scope.curve,
		"chainFamily": scope.chain, "operation": operation,
	} {
		if claims[field] != value {
			return &JsonRpcErr{Code: -32001, Message: "Wallet DKG token scope mismatch"}
		}
	}
	return nil
}
