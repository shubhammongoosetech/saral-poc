package avss

import "fmt"

// ValidateAVSSParameters enforces Cachin et al. (ACM CCS 2002) dual-threshold AVSS condition:
// n - 2*t >= k and k > t
func ValidateAVSSParameters(n, k, t int) error {
	if n <= 0 || k <= 0 || t <= 0 {
		return fmt.Errorf("invalid parameters: n, k, and t must be positive integers (got n=%d, k=%d, t=%d)", n, k, t)
	}
	if n-2*t < k {
		return fmt.Errorf("invalid AVSS parameters: requires n - 2*t >= k (got %d - 2*%d = %d < %d)", n, t, n-2*t, k)
	}
	if k <= t {
		return fmt.Errorf("invalid AVSS parameters: requires k > t (got k=%d, t=%d)", k, t)
	}
	return nil
}

// ValidateProactiveParameters enforces Cachin et al. (ACM CCS 2002) proactive refresh condition:
// k = t + 1 and n > 3*t
func ValidateProactiveParameters(n, k, t int) error {
	if k != t+1 {
		return fmt.Errorf("proactive refresh rejected: Cachin et al. proactive refresh strictly requires ordinary sharing with k = t + 1 (got k=%d, t=%d). Configuration C (k > t+1) dual-threshold AVSS does not support the research paper's proactive refresh protocol", k, t)
	}
	if n <= 3*t {
		return fmt.Errorf("proactive refresh rejected: Cachin et al. proactive refresh requires n > 3*t (got n=%d, t=%d, 3*t=%d)", n, t, 3*t)
	}
	return nil
}

// ValidateHybridVSSParameters verifies the Kate-Huang-Goldberg condition:
// n >= 3t + 2f + 1
func ValidateHybridVSSParameters(n, t, f int) error {
	required := 3*t + 2*f + 1
	if n < required {
		return fmt.Errorf("HybridVSS bound violated: requires n >= 3t + 2f + 1 (got n=%d, required=%d for t=%d, f=%d)", n, required, t, f)
	}
	return nil
}

// HybridVSSEchoQuorum computes the ECHO quorum required before broadcasting READY:
// Formula from Kate-Huang-Goldberg (Figure 1): ceil((n + t + 1) / 2)
func HybridVSSEchoQuorum(n, t int) int {
	return (n + t + 1 + 1) / 2
}

// HybridVSSReadyStepQuorum computes the READY threshold that triggers an honest node to echo READY:
// Formula from Kate-Huang-Goldberg (Figure 1): t + 1
func HybridVSSReadyStepQuorum(t int) int {
	return t + 1
}

// HybridVSSCompletionQuorum computes the number of READY messages required for sharing completion:
// In hybrid model with f crash failures: 2t + f + 1 (or n - t - f)
func HybridVSSCompletionQuorum(n, t, f int) int {
	if f > 0 {
		return 2*t + f + 1
	}
	return 2*t + 1
}

// DualThresholdEchoQuorum computes the ECHO quorum required for generalized reconstruction threshold k > t+1:
// Any two quorums must intersect in at least k honest nodes:
// |Q1 \cap Q2| - t >= k  =>  (2Q - n) - t >= k  =>  2Q >= n + k + t
func DualThresholdEchoQuorum(n, k, t int) int {
	target := n + k + t
	return (target + 1) / 2
}

