// Package llm provides the infrastructure adapter for a vLLM server
// exposing an OpenAI-compatible chat completions API.
package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client talks to a vLLM server's OpenAI-compatible /v1/chat/completions endpoint.
type Client struct {
	baseURL    string
	model      string
	apiKey     string // sent as "Authorization: Bearer <key>"; empty = no header
	httpClient *http.Client
}

// NewClient creates a Client. baseURL should be the vLLM server root
// (e.g. "http://vllm:8000"), model the deployed model name (e.g. "qwen2.5-7b-instruct"),
// apiKey the Bearer token (empty string disables the header).
func NewClient(baseURL, model, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		apiKey:  apiKey,
		httpClient: &http.Client{
			// AI calls can be slow with large contexts — allow up to 2 minutes.
			Timeout: 120 * time.Second,
		},
	}
}

// Ping returns true if the vLLM server is reachable.
func (c *Client) Ping() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Chat sends a system + user message pair and returns the assistant reply
// along with token usage statistics.
func (c *Client) Chat(systemPrompt, userContent string) (reply string, usage Usage, err error) {
	reqBody := chatRequest{
		Model: c.model,
		Messages: []message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userContent},
		},
		Temperature: 0.1,  // low temperature for deterministic security analysis
		MaxTokens:   4096, // enough for structured JSON response
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", Usage{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", Usage{}, fmt.Errorf("POST /v1/chat/completions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", Usage{}, fmt.Errorf("vLLM returned HTTP %d", resp.StatusCode)
	}

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", Usage{}, fmt.Errorf("decode response: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return "", Usage{}, fmt.Errorf("vLLM returned no choices")
	}

	return chatResp.Choices[0].Message.Content, chatResp.Usage, nil
}

// ── OpenAI-compatible request / response DTOs ─────────────────────────────

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []message `json:"messages"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	ID      string   `json:"id"`
	Choices []choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type choice struct {
	Message message `json:"message"`
}

// Usage is exported so the analyst can surface it in domain.AIInsights.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}
