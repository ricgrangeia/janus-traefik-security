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

// AutoBlockAlert carries the enriched payload sent when Janus auto-blocks an IP.
type AutoBlockAlert struct {
	IP          string
	ServiceName string
	Severity    int // 0-10
	Reasoning   string

	// Block duration metadata (zero-valued when permanent / unknown).
	DurationMin  int // applied duration in minutes; 0 = permanent
	OffenseCount int // 1 = first block of this IP in last 24h, 2 = second, ...

	// Enrichment — any field may be zero-valued when unavailable.
	CountryCode string // "US", "--"
	CountryName string
	City        string
	TopRouter   string
	Hits        int
	Count4xx    int
	Count5xx    int
	ErrorRate   float64 // 0.0-1.0
}

// UnblockAlert carries the payload for IP_UNBLOCKED notifications.
type UnblockAlert struct {
	IP     string
	Source string // "ai-review" | "manual" | "intel"
	Reason string // optional explanation
}

// SendUnblockAlert sends a concise IP_UNBLOCKED alert.
func (n *Notifier) SendUnblockAlert(a UnblockAlert) error {
	text := fmt.Sprintf(
		"✅ *IP UNBLOCKED*\n"+
			"IP: `%s`\n"+
			"Source: %s",
		a.IP, a.Source,
	)
	if a.Reason != "" {
		text += fmt.Sprintf("\nReason: \"%s\"", a.Reason)
	}
	return n.send(text)
}

// SendAutoBlockAlert sends a rich IP_BANNED alert with geo + traffic enrichment.
func (n *Notifier) SendAutoBlockAlert(a AutoBlockAlert) error {
	loc := "unknown"
	if a.CountryName != "" || a.City != "" {
		switch {
		case a.City != "" && a.CountryName != "":
			loc = fmt.Sprintf("%s, %s (%s)", a.City, a.CountryName, a.CountryCode)
		case a.CountryName != "":
			loc = fmt.Sprintf("%s (%s)", a.CountryName, a.CountryCode)
		default:
			loc = a.City
		}
	}
	traffic := "no traffic data"
	if a.Hits > 0 {
		traffic = fmt.Sprintf("%d hits · %d 4xx · %d 5xx · %.1f%% error rate",
			a.Hits, a.Count4xx, a.Count5xx, a.ErrorRate*100)
	}
	router := a.TopRouter
	if router == "" {
		router = a.ServiceName
	}

	duration := "permanent"
	if a.DurationMin > 0 {
		if a.OffenseCount > 1 {
			duration = fmt.Sprintf("%d min (offense #%d in 24h)", a.DurationMin, a.OffenseCount)
		} else {
			duration = fmt.Sprintf("%d min (1st offense in 24h)", a.DurationMin)
		}
	}
	text := fmt.Sprintf(
		"🚫 *IP AUTO-BLOCKED*\n"+
			"IP: `%s`\n"+
			"Location: %s\n"+
			"Top Router: `%s`\n"+
			"Traffic: %s\n"+
			"AI Severity: *%d/10*\n"+
			"Duration: %s\n"+
			"Reasoning: \"%s\"\n"+
			"_Review and unblock via the Janus Shield tab if this was a false positive._",
		a.IP, loc, router, traffic, a.Severity, duration, a.Reasoning,
	)
	return n.send(text)
}

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
