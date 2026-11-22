package avss

import (
	"errors"
	"fmt"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

var (
	ErrInvalidSender      = errors.New("sender not in authorized committee")
	ErrDuplicateMessage   = errors.New("duplicate message from sender")
	ErrCommitmentMismatch = errors.New("commitment matrix mismatch")
	ErrPointVerification  = errors.New("cryptographic point verification failed")
)

// NodeIndexInCommittee finds the 1-based index of a node in the committee list. Returns -1 if not found.
func NodeIndexInCommittee(committee []string, nodeID string) int {
	for idx, id := range committee {
		if id == nodeID {
			return idx + 1
		}
	}
	return -1
}

// ProcessSendMessage processes an incoming AVSS_SEND from the dealer:
// Validates cryptographic commitments, stores polynomial slices, and produces ECHO messages for all peers.
func (s *Session) ProcessSendMessage(msg *SendMessage) ([]*EchoMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg.DealerID != s.DealerID {
		return nil, fmt.Errorf("unexpected dealer: got %s, expected %s", msg.DealerID, s.DealerID)
	}
	if !s.messageInScope(msg.SessionID, msg.CommitteeID, msg.RecipientID, msg.Epoch) ||
		!s.validDimensions(msg.Commitments) || len(msg.RowPoly) != s.K || len(msg.RowBlindPoly) != s.K ||
		len(msg.ColPoly) != s.K || len(msg.ColBlindPoly) != s.K {
		return nil, fmt.Errorf("invalid AVSS SEND scope or dimensions")
	}
	hash := HashCommitments(msg.Commitments)
	if s.Curve != cryptography.CurveP256 && (s.SentEcho || s.State == StateSharingCompleted) {
		if hash != s.CommitmentsHash {
			return nil, ErrCommitmentMismatch
		}
		return s.echoMessages(), nil
	}
	if s.State == StateSharingCompleted {
		return nil, ErrSessionAlreadyCompleted
	}

	// 1. Parse Commitment Matrix
	commitMatrix, err := ParseCommitmentMatrixForCurve(msg.Commitments, s.Curve)
	if err != nil {
		s.State = StateSharingFailed
		s.Error = fmt.Sprintf("invalid commitment matrix: %v", err)
		return nil, err
	}

	// 2. Parse Row and Column Polynomials
	rowCoeffs := make([]*cryptography.FieldElement, len(msg.RowPoly))
	rowBlindCoeffs := make([]*cryptography.FieldElement, len(msg.RowBlindPoly))
	colCoeffs := make([]*cryptography.FieldElement, len(msg.ColPoly))
	colBlindCoeffs := make([]*cryptography.FieldElement, len(msg.ColBlindPoly))

	for idx, h := range msg.RowPoly {
		fe, err := s.Curve.ParseScalar(h)
		if err != nil {
			return nil, fmt.Errorf("invalid row poly scalar: %w", err)
		}
		rowCoeffs[idx] = fe
	}
	for idx, h := range msg.RowBlindPoly {
		fe, err := s.Curve.ParseScalar(h)
		if err != nil {
			return nil, fmt.Errorf("invalid row blind poly scalar: %w", err)
		}
		rowBlindCoeffs[idx] = fe
	}
	for idx, h := range msg.ColPoly {
		fe, err := s.Curve.ParseScalar(h)
		if err != nil {
			return nil, fmt.Errorf("invalid col poly scalar: %w", err)
		}
		colCoeffs[idx] = fe
	}
	for idx, h := range msg.ColBlindPoly {
		fe, err := s.Curve.ParseScalar(h)
		if err != nil {
			return nil, fmt.Errorf("invalid col blind poly scalar: %w", err)
		}
		colBlindCoeffs[idx] = fe
	}

	rowPoly := NewPolynomial(rowCoeffs)
	rowBlindPoly := NewPolynomial(rowBlindCoeffs)
	colPoly := NewPolynomial(colCoeffs)
	colBlindPoly := NewPolynomial(colBlindCoeffs)

	// 3. Cryptographic Verification against Commitment Matrix
	selfIndexFE := s.Curve.Scalar(int64(s.SelfIndex))

	if !commitMatrix.VerifyRowPolynomial(selfIndexFE, rowPoly, rowBlindPoly) {
		s.State = StateSharingFailed
		s.Error = "row polynomial verification against commitments failed"
		return nil, ErrCommitmentVerificationFail
	}

	if !commitMatrix.VerifyColPolynomial(selfIndexFE, colPoly, colBlindPoly) {
		s.State = StateSharingFailed
		s.Error = "column polynomial verification against commitments failed"
		return nil, ErrCommitmentVerificationFail
	}

	// 4. Point consistency check: a_i(i) == b_i(i) and a'_i(i) == b'_i(i)
	if !rowPoly.Evaluate(selfIndexFE).Equal(colPoly.Evaluate(selfIndexFE)) {
		s.State = StateSharingFailed
		s.Error = "bivariate point consistency check a_i(i) == b_i(i) failed"
		return nil, ErrCommitmentVerificationFail
	}
	if !rowBlindPoly.Evaluate(selfIndexFE).Equal(colBlindPoly.Evaluate(selfIndexFE)) {
		s.State = StateSharingFailed
		s.Error = "bivariate blinding point consistency check a'_i(i) == b'_i(i) failed"
		return nil, ErrCommitmentVerificationFail
	}

	// 5. Store verified state
	if s.CommitmentsHash != "" && s.CommitmentsHash != hash {
		clear(s.ReceivedEchos)
		clear(s.ReceivedReadys)
	}
	s.Commitments = commitMatrix
	s.CommitmentsHash = hash
	s.RowPoly = rowPoly
	s.RowBlindPoly = rowBlindPoly
	s.ColPoly = colPoly
	s.ColBlindPoly = colBlindPoly
	s.State = StateEchoCollecting
	s.UpdatedAt = time.Now()

	s.SentEcho = true
	return s.echoMessages(), nil
}

// echoMessages must be called with the session locked.
func (s *Session) echoMessages() []*EchoMessage {
	if s.RowPoly == nil {
		return nil
	}
	now := time.Now().UnixMilli()
	echos := make([]*EchoMessage, len(s.Committee))
	commitments := s.Commitments.ToHexMatrix()

	for idx, recipientID := range s.Committee {
		recipientIndexFE := s.Curve.Scalar(int64(idx + 1))
		// p_{self, recipient} = a_{self}(recipient)
		point := s.RowPoly.Evaluate(recipientIndexFE)
		blindPoint := s.RowBlindPoly.Evaluate(recipientIndexFE)

		echos[idx] = &EchoMessage{
			SessionID:   s.SessionID,
			CommitteeID: s.CommitteeID,
			SenderID:    s.SelfID,
			RecipientID: recipientID,
			Epoch:       s.Epoch,
			Commitments: commitments,
			Point:       point.Hex(),
			BlindPoint:  blindPoint.Hex(),
			Timestamp:   now,
		}
	}
	return echos
}

// ProcessEchoMessage processes an incoming AVSS_ECHO:
// Verifies point against commitment matrix, updates session state, checks for interpolation fallback,
// and returns a ReadyMessage if the READY threshold is met.
func (s *Session) ProcessEchoMessage(echo *EchoMessage) ([]*ReadyMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.messageInScope(echo.SessionID, echo.CommitteeID, echo.RecipientID, echo.Epoch) || !s.validDimensions(echo.Commitments) {
		return nil, fmt.Errorf("invalid AVSS ECHO scope or dimensions")
	}
	senderIdx := NodeIndexInCommittee(s.Committee, echo.SenderID)
	if senderIdx == -1 {
		return nil, ErrInvalidSender
	}

	if _, exists := s.ReceivedEchos[echo.SenderID]; exists {
		return nil, ErrDuplicateMessage
	}

	// Check commitment matrix consistency
	echoHash := HashCommitments(echo.Commitments)
	matrix := s.Commitments
	if s.CommitmentsHash == "" {
		var err error
		matrix, err = ParseCommitmentMatrixForCurve(echo.Commitments, s.Curve)
		if err != nil {
			return nil, fmt.Errorf("failed to parse commitment matrix from echo: %w", err)
		}
	} else if s.CommitmentsHash != echoHash {
		return nil, ErrCommitmentMismatch
	}

	// Parse points
	p, err := s.Curve.ParseScalar(echo.Point)
	if err != nil {
		return nil, fmt.Errorf("invalid echo point: %w", err)
	}
	pPrime, err := s.Curve.ParseScalar(echo.BlindPoint)
	if err != nil {
		return nil, fmt.Errorf("invalid echo blind point: %w", err)
	}

	// Verify point cryptographically against C: Commit(p, p') == C(sender, self)
	senderFE := s.Curve.Scalar(int64(senderIdx))
	selfFE := s.Curve.Scalar(int64(s.SelfIndex))
	if !matrix.VerifyPoint(senderFE, selfFE, p, pPrime) {
		return nil, ErrPointVerification
	}

	// If self already has colPoly b_{self}(x), check b_{self}(sender) == p
	if s.ColPoly != nil {
		if !s.ColPoly.Evaluate(senderFE).Equal(p) {
			return nil, fmt.Errorf("%w: mismatch with local column polynomial", ErrPointVerification)
		}
		if !s.ColBlindPoly.Evaluate(senderFE).Equal(pPrime) {
			return nil, fmt.Errorf("%w: mismatch with local column blinding polynomial", ErrPointVerification)
		}
	}

	s.Commitments = matrix
	s.CommitmentsHash = echoHash
	s.ReceivedEchos[echo.SenderID] = echo

	// Interpolation Fallback: If SEND was missing, can we interpolate from k valid points?
	if s.ColPoly == nil && len(s.ReceivedEchos) >= s.K {
		xs := make([]*cryptography.FieldElement, 0, s.K)
		ys := make([]*cryptography.FieldElement, 0, s.K)
		ysBlind := make([]*cryptography.FieldElement, 0, s.K)

		for sID, e := range s.ReceivedEchos {
			sIndex := NodeIndexInCommittee(s.Committee, sID)
			ptVal, _ := s.Curve.ParseScalar(e.Point)
			ptBlindVal, _ := s.Curve.ParseScalar(e.BlindPoint)
			xs = append(xs, s.Curve.Scalar(int64(sIndex)))
			ys = append(ys, ptVal)
			ysBlind = append(ysBlind, ptBlindVal)
			if len(xs) == s.K {
				break
			}
		}

		interpolatedCol, err := InterpolateUnivariate(xs, ys)
		if err == nil {
			interpolatedColBlind, errBlind := InterpolateUnivariate(xs, ysBlind)
			if errBlind == nil {
				// Verify interpolated polynomials against commitments
				if s.Commitments.VerifyColPolynomial(selfFE, interpolatedCol, interpolatedColBlind) {
					s.ColPoly = interpolatedCol
					s.ColBlindPoly = interpolatedColBlind
					s.RowPoly = interpolatedCol // Symmetric bivariate
					s.RowBlindPoly = interpolatedColBlind
				}
			}
		}
	}

	// Count valid matching READY messages in backlog
	readyCount := 0
	for _, r := range s.ReceivedReadys {
		if HashCommitments(r.Commitments) == s.CommitmentsHash {
			readyCount++
		}
	}

	var readyMsgsToSend []*ReadyMessage
	// Check if we can send READY (via n-t ECHOs rule OR t+1 READYs amplification rule)
	if !s.SentReady && s.RowPoly != nil && (len(s.ReceivedEchos) >= s.N-s.T || readyCount >= s.T+1) {
		readyMsgsToSend = s.generateReadyMessages()
	}

	// Check if completion rule is satisfied (>= k + t READYs)
	if s.State != StateSharingCompleted && s.RowPoly != nil && readyCount >= s.K+s.T {
		s.Share = s.RowPoly.Coeffs[0]
		s.BlindShare = s.RowBlindPoly.Coeffs[0]
		selfIndexFE := s.Curve.Scalar(int64(s.SelfIndex))
		s.PublicShareCommitment = s.Commitments.ComputeShareCommitment(selfIndexFE)
		s.PublicSecretCommitment = s.Commitments.SecretCommitment()
		s.State = StateSharingCompleted
		s.UpdatedAt = time.Now()
	}

	return readyMsgsToSend, nil
}

// ProcessReadyMessage processes an incoming AVSS_READY:
// Records ready message, checks for ready amplification (>= t+1), and evaluates sharing completion (>= k+t).
func (s *Session) ProcessReadyMessage(ready *ReadyMessage) (bool, []*ReadyMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.messageInScope(ready.SessionID, ready.CommitteeID, ready.RecipientID, ready.Epoch) || !s.validDimensions(ready.Commitments) {
		return false, nil, fmt.Errorf("invalid AVSS READY scope or dimensions")
	}
	senderIdx := NodeIndexInCommittee(s.Committee, ready.SenderID)
	if senderIdx == -1 {
		return false, nil, ErrInvalidSender
	}

	if _, exists := s.ReceivedReadys[ready.SenderID]; exists {
		return false, nil, ErrDuplicateMessage
	}

	readyHash := HashCommitments(ready.Commitments)
	matrix := s.Commitments
	if s.CommitmentsHash == "" {
		var err error
		matrix, err = ParseCommitmentMatrixForCurve(ready.Commitments, s.Curve)
		if err != nil {
			return false, nil, fmt.Errorf("failed to parse commitments from ready: %w", err)
		}
	} else if s.CommitmentsHash != readyHash {
		return false, nil, ErrCommitmentMismatch
	}
	if s.Curve != cryptography.CurveP256 {
		point, pointErr := s.Curve.ParseScalar(ready.Point)
		blind, blindErr := s.Curve.ParseScalar(ready.BlindPoint)
		if pointErr != nil || blindErr != nil || !matrix.VerifyPoint(s.Curve.Scalar(int64(senderIdx)),
			s.Curve.Scalar(int64(s.SelfIndex)), point, blind) {
			return false, nil, ErrPointVerification
		}
	}
	s.Commitments = matrix
	s.CommitmentsHash = readyHash
	s.ReceivedReadys[ready.SenderID] = ready

	var readyMsgsToSend []*ReadyMessage
	// Amplification rule: if >= t + 1 READYs received and not yet sent READY and we have polynomials
	if !s.SentReady && s.RowPoly != nil && len(s.ReceivedReadys) >= s.T+1 {
		readyMsgsToSend = s.generateReadyMessages()
	}

	// Completion rule: if >= k + t READYs received and we have polynomials
	if s.State != StateSharingCompleted && s.RowPoly != nil && len(s.ReceivedReadys) >= s.K+s.T {
		s.Share = s.RowPoly.Coeffs[0]
		s.BlindShare = s.RowBlindPoly.Coeffs[0]
		selfIndexFE := s.Curve.Scalar(int64(s.SelfIndex))
		s.PublicShareCommitment = s.Commitments.ComputeShareCommitment(selfIndexFE)
		s.PublicSecretCommitment = s.Commitments.SecretCommitment()
		s.State = StateSharingCompleted
		s.UpdatedAt = time.Now()
		return true, readyMsgsToSend, nil
	}

	return false, readyMsgsToSend, nil
}

func (s *Session) messageInScope(session, committee, recipient string, epoch uint64) bool {
	return session == s.SessionID && committee == s.CommitteeID && recipient == s.SelfID && epoch == s.Epoch
}

func (s *Session) validDimensions(matrix [][]string) bool {
	if len(matrix) != s.K {
		return false
	}
	for _, row := range matrix {
		if len(row) != s.K {
			return false
		}
	}
	return true
}

// generateReadyMessages creates READY messages for all peers in the committee
func (s *Session) generateReadyMessages() []*ReadyMessage {
	now := time.Now().UnixMilli()
	readys := make([]*ReadyMessage, len(s.Committee))
	hexCommit := s.Commitments.ToHexMatrix()

	for idx, recipientID := range s.Committee {
		recipientIndexFE := s.Curve.Scalar(int64(idx + 1))
		pt := s.RowPoly.Evaluate(recipientIndexFE)
		blindPt := s.RowBlindPoly.Evaluate(recipientIndexFE)

		readys[idx] = &ReadyMessage{
			SessionID:   s.SessionID,
			CommitteeID: s.CommitteeID,
			SenderID:    s.SelfID,
			RecipientID: recipientID,
			Epoch:       s.Epoch,
			Commitments: hexCommit,
			Point:       pt.Hex(),
			BlindPoint:  blindPt.Hex(),
			Timestamp:   now,
		}
	}
	s.SentReady = true
	s.State = StateReadyCollecting
	return readys
}

// ProcessRecoveryRequest handles incoming recovery request from a crashed or recovering peer
func (s *Session) ProcessRecoveryRequest(req *RecoveryRequestMessage) (*RecoveryResponseMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reqIdx := NodeIndexInCommittee(s.Committee, req.RequesterID)
	if reqIdx == -1 {
		return nil, ErrInvalidSender
	}

	if s.Commitments == nil {
		return nil, errors.New("cannot assist recovery: commitments not yet established")
	}

	var ptHex, ptBlindHex string
	if s.RowPoly != nil && s.RowBlindPoly != nil {
		reqIndexFE := s.Curve.Scalar(int64(reqIdx))
		pt := s.RowPoly.Evaluate(reqIndexFE)
		blindPt := s.RowBlindPoly.Evaluate(reqIndexFE)
		ptHex = pt.Hex()
		ptBlindHex = blindPt.Hex()
	}

	return &RecoveryResponseMessage{
		SessionID:   s.SessionID,
		CommitteeID: s.CommitteeID,
		ResponderID: s.SelfID,
		RecipientID: req.RequesterID,
		Epoch:       s.Epoch,
		Commitments: s.Commitments.ToHexMatrix(),
		Point:       ptHex,
		BlindPoint:  ptBlindHex,
		Timestamp:   time.Now().UnixMilli(),
	}, nil
}

// ProcessRecoveryResponse processes a received recovery response to rebuild missing state
func (s *Session) ProcessRecoveryResponse(resp *RecoveryResponseMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	respIdx := NodeIndexInCommittee(s.Committee, resp.ResponderID)
	if respIdx == -1 {
		return ErrInvalidSender
	}

	// Verify commitment matrix consistency
	respHash := HashCommitments(resp.Commitments)
	matrix := s.Commitments
	if s.CommitmentsHash == "" {
		var err error
		matrix, err = ParseCommitmentMatrixForCurve(resp.Commitments, s.Curve)
		if err != nil {
			return fmt.Errorf("failed to parse commitments from recovery response: %w", err)
		}
	} else if s.CommitmentsHash != respHash {
		return ErrCommitmentMismatch
	}

	if resp.Point != "" && resp.BlindPoint != "" {
		p, err := s.Curve.ParseScalar(resp.Point)
		if err != nil {
			return err
		}
		pPrime, err := s.Curve.ParseScalar(resp.BlindPoint)
		if err != nil {
			return err
		}

		senderFE := s.Curve.Scalar(int64(respIdx))
		selfFE := s.Curve.Scalar(int64(s.SelfIndex))
		if !matrix.VerifyPoint(senderFE, selfFE, p, pPrime) {
			return ErrPointVerification
		}

		// Store in received echoes if not present
		if _, exists := s.ReceivedEchos[resp.ResponderID]; !exists {
			s.ReceivedEchos[resp.ResponderID] = &EchoMessage{
				SessionID:   s.SessionID,
				CommitteeID: s.CommitteeID,
				SenderID:    resp.ResponderID,
				RecipientID: s.SelfID,
				Epoch:       s.Epoch,
				Commitments: resp.Commitments,
				Point:       resp.Point,
				BlindPoint:  resp.BlindPoint,
				Timestamp:   resp.Timestamp,
			}
		}
	}

	s.Commitments = matrix
	s.CommitmentsHash = respHash
	return nil
}
