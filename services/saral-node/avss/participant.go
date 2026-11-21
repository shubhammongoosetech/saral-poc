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

	if s.State == StateSharingCompleted {
		return nil, ErrSessionAlreadyCompleted
	}
	if msg.DealerID != s.DealerID {
		return nil, fmt.Errorf("unexpected dealer: got %s, expected %s", msg.DealerID, s.DealerID)
	}

	// 1. Parse Commitment Matrix
	commitMatrix, err := ParseCommitmentMatrixFromHex(msg.Commitments)
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
		fe, err := cryptography.NewFieldElementFromHex(h)
		if err != nil {
			return nil, fmt.Errorf("invalid row poly scalar: %w", err)
		}
		rowCoeffs[idx] = fe
	}
	for idx, h := range msg.RowBlindPoly {
		fe, err := cryptography.NewFieldElementFromHex(h)
		if err != nil {
			return nil, fmt.Errorf("invalid row blind poly scalar: %w", err)
		}
		rowBlindCoeffs[idx] = fe
	}
	for idx, h := range msg.ColPoly {
		fe, err := cryptography.NewFieldElementFromHex(h)
		if err != nil {
			return nil, fmt.Errorf("invalid col poly scalar: %w", err)
		}
		colCoeffs[idx] = fe
	}
	for idx, h := range msg.ColBlindPoly {
		fe, err := cryptography.NewFieldElementFromHex(h)
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
	selfIndexFE := cryptography.NewFieldElement(int64(s.SelfIndex))

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
	s.Commitments = commitMatrix
	s.CommitmentsHash = HashCommitments(msg.Commitments)
	s.RowPoly = rowPoly
	s.RowBlindPoly = rowBlindPoly
	s.ColPoly = colPoly
	s.ColBlindPoly = colBlindPoly
	s.State = StateEchoCollecting
	s.UpdatedAt = time.Now()

	// 6. Generate ECHO messages for all participants in the committee
	now := time.Now().UnixMilli()
	echos := make([]*EchoMessage, len(s.Committee))

	for idx, recipientID := range s.Committee {
		recipientIndexFE := cryptography.NewFieldElement(int64(idx + 1))
		// p_{self, recipient} = a_{self}(recipient)
		point := rowPoly.Evaluate(recipientIndexFE)
		blindPoint := rowBlindPoly.Evaluate(recipientIndexFE)

		echos[idx] = &EchoMessage{
			SessionID:   s.SessionID,
			CommitteeID: s.CommitteeID,
			SenderID:    s.SelfID,
			RecipientID: recipientID,
			Epoch:       s.Epoch,
			Commitments: msg.Commitments,
			Point:       point.Hex(),
			BlindPoint:  blindPoint.Hex(),
			Timestamp:   now,
		}
	}
	s.SentEcho = true

	return echos, nil
}

// ProcessEchoMessage processes an incoming AVSS_ECHO:
// Verifies point against commitment matrix, updates session state, checks for interpolation fallback,
// and returns a ReadyMessage if the READY threshold is met.
func (s *Session) ProcessEchoMessage(echo *EchoMessage) ([]*ReadyMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	senderIdx := NodeIndexInCommittee(s.Committee, echo.SenderID)
	if senderIdx == -1 {
		return nil, ErrInvalidSender
	}

	if _, exists := s.ReceivedEchos[echo.SenderID]; exists {
		return nil, ErrDuplicateMessage
	}

	// Check commitment matrix consistency
	echoHash := HashCommitments(echo.Commitments)
	if s.CommitmentsHash == "" {
		s.CommitmentsHash = echoHash
		var err error
		s.Commitments, err = ParseCommitmentMatrixFromHex(echo.Commitments)
		if err != nil {
			return nil, fmt.Errorf("failed to parse commitment matrix from echo: %w", err)
		}
	} else if s.CommitmentsHash != echoHash {
		return nil, ErrCommitmentMismatch
	}

	// Parse points
	p, err := cryptography.NewFieldElementFromHex(echo.Point)
	if err != nil {
		return nil, fmt.Errorf("invalid echo point: %w", err)
	}
	pPrime, err := cryptography.NewFieldElementFromHex(echo.BlindPoint)
	if err != nil {
		return nil, fmt.Errorf("invalid echo blind point: %w", err)
	}

	// Verify point cryptographically against C: Commit(p, p') == C(sender, self)
	senderFE := cryptography.NewFieldElement(int64(senderIdx))
	selfFE := cryptography.NewFieldElement(int64(s.SelfIndex))
	if !s.Commitments.VerifyPoint(senderFE, selfFE, p, pPrime) {
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

	s.ReceivedEchos[echo.SenderID] = echo

	// Interpolation Fallback: If SEND was missing, can we interpolate from k valid points?
	if s.ColPoly == nil && len(s.ReceivedEchos) >= s.K {
		xs := make([]*cryptography.FieldElement, 0, s.K)
		ys := make([]*cryptography.FieldElement, 0, s.K)
		ysBlind := make([]*cryptography.FieldElement, 0, s.K)

		for sID, e := range s.ReceivedEchos {
			sIndex := NodeIndexInCommittee(s.Committee, sID)
			ptVal, _ := cryptography.NewFieldElementFromHex(e.Point)
			ptBlindVal, _ := cryptography.NewFieldElementFromHex(e.BlindPoint)
			xs = append(xs, cryptography.NewFieldElement(int64(sIndex)))
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
		selfIndexFE := cryptography.NewFieldElement(int64(s.SelfIndex))
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

	senderIdx := NodeIndexInCommittee(s.Committee, ready.SenderID)
	if senderIdx == -1 {
		return false, nil, ErrInvalidSender
	}

	if _, exists := s.ReceivedReadys[ready.SenderID]; exists {
		return false, nil, ErrDuplicateMessage
	}

	readyHash := HashCommitments(ready.Commitments)
	if s.CommitmentsHash == "" {
		s.CommitmentsHash = readyHash
		var err error
		s.Commitments, err = ParseCommitmentMatrixFromHex(ready.Commitments)
		if err != nil {
			return false, nil, fmt.Errorf("failed to parse commitments from ready: %w", err)
		}
	} else if s.CommitmentsHash != readyHash {
		return false, nil, ErrCommitmentMismatch
	}

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
		selfIndexFE := cryptography.NewFieldElement(int64(s.SelfIndex))
		s.PublicShareCommitment = s.Commitments.ComputeShareCommitment(selfIndexFE)
		s.PublicSecretCommitment = s.Commitments.SecretCommitment()
		s.State = StateSharingCompleted
		s.UpdatedAt = time.Now()
		return true, readyMsgsToSend, nil
	}

	return false, readyMsgsToSend, nil
}

// generateReadyMessages creates READY messages for all peers in the committee
func (s *Session) generateReadyMessages() []*ReadyMessage {
	now := time.Now().UnixMilli()
	readys := make([]*ReadyMessage, len(s.Committee))
	hexCommit := s.Commitments.ToHexMatrix()

	for idx, recipientID := range s.Committee {
		recipientIndexFE := cryptography.NewFieldElement(int64(idx + 1))
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
		reqIndexFE := cryptography.NewFieldElement(int64(reqIdx))
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
	if s.CommitmentsHash == "" {
		s.CommitmentsHash = respHash
		var err error
		s.Commitments, err = ParseCommitmentMatrixFromHex(resp.Commitments)
		if err != nil {
			return fmt.Errorf("failed to parse commitments from recovery response: %w", err)
		}
	} else if s.CommitmentsHash != respHash {
		return ErrCommitmentMismatch
	}

	if resp.Point != "" && resp.BlindPoint != "" {
		p, err := cryptography.NewFieldElementFromHex(resp.Point)
		if err != nil {
			return err
		}
		pPrime, err := cryptography.NewFieldElementFromHex(resp.BlindPoint)
		if err != nil {
			return err
		}

		senderFE := cryptography.NewFieldElement(int64(respIdx))
		selfFE := cryptography.NewFieldElement(int64(s.SelfIndex))
		if !s.Commitments.VerifyPoint(senderFE, selfFE, p, pPrime) {
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

	return nil
}

