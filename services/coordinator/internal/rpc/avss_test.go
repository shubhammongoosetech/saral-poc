package rpc

import (
	"testing"
)

func TestValidateAVSSParameters(t *testing.T) {
	// Configuration A: n=15, t=4, k=5
	if err := ValidateAVSSParameters(15, 5, 4); err != nil {
		t.Fatalf("Configuration A should be valid: %v", err)
	}

	// Configuration B: n=5, t=1, k=2
	if err := ValidateAVSSParameters(5, 2, 1); err != nil {
		t.Fatalf("Configuration B should be valid: %v", err)
	}

	// Configuration C: n=5, t=1, k=3 (dual-threshold AVSS)
	if err := ValidateAVSSParameters(5, 3, 1); err != nil {
		t.Fatalf("Configuration C should be valid for AVSS: %v", err)
	}

	// Invalid: n - 2*t < k (5 - 2*1 = 3 < 4)
	if err := ValidateAVSSParameters(5, 4, 1); err == nil {
		t.Fatalf("Expected error for n - 2*t < k")
	}

	// Invalid: k <= t (k=2, t=2)
	if err := ValidateAVSSParameters(10, 2, 2); err == nil {
		t.Fatalf("Expected error for k <= t")
	}

	// Invalid: negative or zero
	if err := ValidateAVSSParameters(0, 5, 2); err == nil {
		t.Fatalf("Expected error for n=0")
	}
}

func TestValidateProactiveParameters(t *testing.T) {
	// Configuration A: n=15, t=4, k=5 (k = t+1 = 5, n = 15 > 3*4 = 12)
	if err := ValidateProactiveParameters(15, 5, 4); err != nil {
		t.Fatalf("Configuration A should be valid for proactive refresh: %v", err)
	}

	// Configuration B: n=5, t=1, k=2 (k = t+1 = 2, n = 5 > 3*1 = 3)
	if err := ValidateProactiveParameters(5, 2, 1); err != nil {
		t.Fatalf("Configuration B should be valid for proactive refresh: %v", err)
	}

	// Configuration C: n=5, t=1, k=3 (k != t+1)
	// MUST BE REJECTED per Cachin et al. 2002 specification
	if err := ValidateProactiveParameters(5, 3, 1); err == nil {
		t.Fatalf("Configuration C MUST be rejected for proactive refresh (k=3 != t+1=2)")
	}

	// Invalid: n <= 3*t (n=12, t=4, 3*t=12)
	if err := ValidateProactiveParameters(12, 5, 4); err == nil {
		t.Fatalf("Expected error when n <= 3*t")
	}
}

