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

