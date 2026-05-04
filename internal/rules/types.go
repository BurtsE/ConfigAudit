package rules

import (
	"fmt"
	"sort"
	"sync"
)

type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

type Finding struct {
	Severity       Severity `json:"severity"`
	Rule           string   `json:"rule"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
	Path           string   `json:"path,omitempty"`
}

type Rule interface {
	Name() string
	Check(cfg map[string]any) ([]Finding, error)
}

type RuleRegistry struct {
	rules []Rule
}

func NewRuleRegistry() *RuleRegistry {
	return &RuleRegistry{
		rules: make([]Rule, 0),
	}
}

func (r *RuleRegistry) Register(rule Rule) {
	r.rules = append(r.rules, rule)
}

func (r *RuleRegistry) Run(cfg map[string]any) ([]Finding, error) {
	if len(r.rules) == 0 {
		return []Finding{}, nil
	}

	var allFindings []Finding
	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, len(r.rules))
	findingsChan := make(chan []Finding, len(r.rules))

	for _, rule := range r.rules {
		wg.Add(1)
		go func(r Rule) {
			defer wg.Done()

			findings, err := r.Check(cfg)
			if err != nil {
				errChan <- fmt.Errorf("rule %s failed: %w", r.Name(), err)
				return
			}

			findingsChan <- findings
		}(rule)
	}

	go func() {
		wg.Wait()
		close(errChan)
		close(findingsChan)
	}()

	for err := range errChan {
		return nil, err
	}

	for findings := range findingsChan {
		mu.Lock()
		allFindings = append(allFindings, findings...)
		mu.Unlock()
	}

	sort.Slice(allFindings, func(i, j int) bool {
		severityOrder := map[Severity]int{
			SeverityHigh:   3,
			SeverityMedium: 2,
			SeverityLow:    1,
		}
		return severityOrder[allFindings[i].Severity] > severityOrder[allFindings[j].Severity]
	})

	return allFindings, nil
}

func (r *RuleRegistry) GetRuleCount() int {
	return len(r.rules)
}
