// Package telegram sends threat alerts to a Telegram bot.
package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Notifier sends messages to a Telegram chat via the Bot API.
type Notifier struct {
	token  string
	chatID string
	client *http.Client
}

// NewNotifier creates a Notifier. token is the Bot API token and chatID is the
// target chat or channel ID. Both must be non-empty for the notifier to be enabled.
func NewNotifier(token, chatID string) *Notifier {
	return &Notifier{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled returns true when both token and chatID are configured.
func (n *Notifier) Enabled() bool { return n.token != "" && n.chatID != "" }

// SendThreatAlert sends a formatted bot-scan threat alert.
// serviceName, classification, reasoning, and fix are inserted into the message template.
func (n *Notifier) SendThreatAlert(serviceName, classification, reasoning, fix string) error {
	text := fmt.Sprintf(
		"🚨 *AI THREAT DETECTION*\n"+
			"Service: `%s`\n"+
			"AI Classification: *%s*\n"+
			"Reasoning: \"%s\"\n"+
			"Recommended Fix: %s",
		serviceName, classification, reasoning, fix,
	)
	return n.send(text)
}

// sendMessageReq is the Telegram Bot API sendMessage payload.
type sendMessageReq struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

func (n *Notifier) send(text string) error {
	payload, err := json.Marshal(sendMessageReq{
		ChatID:    n.chatID,
		Text:      text,
		ParseMode: "Markdown",
	})
	if err != nil {
		return fmt.Errorf("telegram: marshal: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.token)
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("telegram: POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram: HTTP %d", resp.StatusCode)
	}
	return nil
}
