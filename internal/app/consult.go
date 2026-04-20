package app

import (
	"fmt"

	"github.com/janus-project/janus/internal/infrastructure/llm"
	"github.com/janus-project/janus/internal/infrastructure/storage"
)

// ConsultService performs on-demand AI executive summaries over audit history.
type ConsultService struct {
	client *llm.Client
	repo   storage.Store
}

// NewConsultService creates a ConsultService. Both arguments are required.
func NewConsultService(client *llm.Client, repo storage.Store) *ConsultService {
	return &ConsultService{client: client, repo: repo}
}

// ExecutiveSummary sends the full audit history to Janus-AI and returns a
// 3-paragraph strategic summary. Returns an error if history is empty or
// the LLM call fails.
func (s *ConsultService) ExecutiveSummary() (string, int, error) {
	history := s.repo.History()
	if len(history) == 0 {
		return "", 0, fmt.Errorf("no audit history available yet — run at least one AI audit first")
	}

	ctx := llm.BuildConsultContext(history)
	reply, usage, err := s.client.Chat(llm.ConsultPrompt, ctx)
	if err != nil {
		return "", 0, fmt.Errorf("LLM consult: %w", err)
	}
	return reply, usage.TotalTokens, nil
}
