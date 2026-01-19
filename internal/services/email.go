package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/zero469/opencode-relay-server/internal/config"
)

type EmailService struct {
	apiKey    string
	emailFrom string
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{
		apiKey:    cfg.ResendAPIKey,
		emailFrom: cfg.EmailFrom,
	}
}

type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Html    string   `json:"html"`
}

func (s *EmailService) SendVerificationCode(to, code string) error {
	if s.apiKey == "" {
		return fmt.Errorf("RESEND_API_KEY not configured")
	}

	html := fmt.Sprintf(`
		<div style="font-family: sans-serif; max-width: 400px; margin: 0 auto;">
			<h2 style="color: #333;">Verify your email</h2>
			<p>Your verification code is:</p>
			<div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 32px; letter-spacing: 8px; font-weight: bold; margin: 20px 0;">
				%s
			</div>
			<p style="color: #666; font-size: 14px;">This code expires in 10 minutes.</p>
		</div>
	`, code)

	reqBody := resendRequest{
		From:    s.emailFrom,
		To:      []string{to},
		Subject: "Your verification code",
		Html:    html,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("resend API error: %d", resp.StatusCode)
	}

	return nil
}
