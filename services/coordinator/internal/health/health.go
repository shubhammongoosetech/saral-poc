package health

import (
	"encoding/json"
	"net/http"
	"time"
)

type CoordinatorHealthResponse struct {
	Status           string `json:"status"`
	Service          string `json:"service"`
	Domain           string `json:"domain"`
	EnrolledNodes    int    `json:"enrolledNodes"`
	PeerCoordinators int    `json:"peerCoordinators"`
	Timestamp        string `json:"timestamp"`
}

func NewHandler(domain string, getNodeCount func() int, getPeerCount func() int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := CoordinatorHealthResponse{
			Status:           "ok",
			Service:          "saral-coordinator",
			Domain:           domain,
			EnrolledNodes:    getNodeCount(),
			PeerCoordinators: getPeerCount(),
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}
