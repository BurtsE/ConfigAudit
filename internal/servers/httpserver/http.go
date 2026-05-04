package httpsrv

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/BurtsE/config-audit/internal/parser"
	"github.com/BurtsE/config-audit/internal/rules"
)

type Server struct {
	Registry *rules.RuleRegistry
	Server   *http.Server
	Port     int
}

func NewHttpServer(port int, registry *rules.RuleRegistry) *Server {
	srv := &Server{Registry: registry, Port: port}
	h := srv.initHandler()
	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		Handler:        h,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	srv.Server = s
	return srv
}

func (s *Server) initHandler() *http.ServeMux {
	handler := http.NewServeMux()
	handler.HandleFunc("/config/check", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Получен запрос на проверку конфигурации")
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		format, err := parser.DetectFormat(data)
		if err != nil {
			http.Error(w, "Failed to detect config format", http.StatusBadRequest)
			return
		}

		cfg, err := parser.ParseConfig(data, format)
		if err != nil {
			http.Error(w, "Failed to parse config: "+err.Error(), http.StatusBadRequest)
			return
		}

		findings, err := s.Registry.Run(cfg)
		if err != nil {
			http.Error(w, "Failed to run security checks: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"findings": findings,
			"summary": map[string]int{
				"total":  len(findings),
				"high":   countSeverity(findings, "HIGH"),
				"medium": countSeverity(findings, "MEDIUM"),
				"low":    countSeverity(findings, "LOW"),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	return handler
}

func countSeverity(findings []rules.Finding, severity string) int {
	count := 0
	for _, finding := range findings {
		if string(finding.Severity) == severity {
			count++
		}
	}
	return count
}

func (s *Server) Start() error {
	return s.Server.ListenAndServe()
}

func (s *Server) Stop() error {
	return s.Server.Close()
}
