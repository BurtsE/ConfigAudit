package grpcsrv

import (
	"context"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/BurtsE/config-audit/internal/parser"
	"github.com/BurtsE/config-audit/internal/rules"
	pb "github.com/BurtsE/config-audit/proto"
)

type Server struct {
	Registry *rules.RuleRegistry
	pb.UnimplementedConfigAuditServiceServer
}

func NewGrpcServer(registry *rules.RuleRegistry) *Server {
	return &Server{
		Registry: registry,
	}
}

func (s *Server) AuditConfig(ctx context.Context, req *pb.AuditConfigRequest) (*pb.AuditConfigResponse, error) {
	log.Println("Получен запрос на проверку конфигурации")
	if len(req.ConfigData) == 0 {
		return nil, fmt.Errorf("config data cannot be empty")
	}

	format := req.ConfigFormat
	if format == "" {
		detectedFormat, err := parser.DetectFormat(req.ConfigData)
		if err != nil {
			return nil, fmt.Errorf("failed to detect config format: %v", err)
		}
		format = detectedFormat
	}

	cfg, err := parser.ParseConfig(req.ConfigData, format)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	findings, err := s.Registry.Run(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to run security checks: %v", err)
	}

	pbFindings := make([]*pb.Finding, len(findings))
	for i, finding := range findings {
		pbFindings[i] = &pb.Finding{
			Severity:       string(finding.Severity),
			Rule:           finding.Rule,
			Message:        finding.Message,
			Recommendation: finding.Recommendation,
			Path:           finding.Path,
		}
	}

	summary := &pb.Summary{
		Total:  int32(len(findings)),
		High:   int32(countSeverity(findings, "HIGH")),
		Medium: int32(countSeverity(findings, "MEDIUM")),
		Low:    int32(countSeverity(findings, "LOW")),
	}

	return &pb.AuditConfigResponse{
		Findings: pbFindings,
		Summary:  summary,
	}, nil
}

func (s *Server) GetServerInfo(ctx context.Context, req *pb.GetServerInfoRequest) (*pb.ServerInfo, error) {
	return &pb.ServerInfo{
		Version:     "1.0.0",
		ServiceName: "ConfigAuditService",
	}, nil
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

func CreateServer(registry *rules.RuleRegistry) *grpc.Server {
	server := grpc.NewServer()
	pb.RegisterConfigAuditServiceServer(server, NewGrpcServer(registry))

	reflection.Register(server)

	return server
}

func StartServer(server *grpc.Server, listener net.Listener) error {
	return server.Serve(listener)
}
