package service

import (
	"encoding/json"
	"net/http"

	health "github.com/ArmornetIO/ota/health"
)

// healthMux mirrors armornet's /healthz (code only) and /status (JSON) on
// net/http for a pod with no REST server; both read the cached report.
func (s *Server) healthMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/status", s.handleStatus)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	report := s.health.Cached()
	w.WriteHeader(health.HTTPStatus(report.Status))
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	report := s.health.Cached()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(health.HTTPStatus(report.Status))
	_ = json.NewEncoder(w).Encode(report)
}
