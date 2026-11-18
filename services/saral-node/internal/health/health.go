package health

import (
	"encoding/json"
	"net/http"
	"time"
)

type NodeHealthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	NodeID    string `json:"nodeId"`
	Domain    string `json:"domain"`
	UptimeSec int64  `json:"uptimeSec"`
	Timestamp string `json:"timestamp"`
}

func NewHandler(nodeID, domain string, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := NodeHealthResponse{
			Status:    "HEALTHY",
			Service:   "saral-node",
			NodeID:    nodeID,
			Domain:    domain,
			UptimeSec: int64(time.Since(startTime).Seconds()),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}
