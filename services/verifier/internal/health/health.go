package health

import (
	"encoding/json"
	"net/http"
	"time"
)

type StatusResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Domain    string `json:"domain"`
	Ready     bool   `json:"ready"`
	Timestamp string `json:"timestamp"`
}

func Handler(domain string, isReady func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ready := isReady()
		status := "ok"
		statusCode := http.StatusOK
		if !ready {
			status = "not_ready"
			statusCode = http.StatusServiceUnavailable
		}

		resp := StatusResponse{
			Status:    status,
			Service:   "saral-verifier",
			Domain:    domain,
			Ready:     ready,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

