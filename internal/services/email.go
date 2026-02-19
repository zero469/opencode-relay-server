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
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<div style="font-family: Arial, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px;">
	<h2 style="color: #333;">OpenCode Anywhere</h2>
	<p>Hello,</p>
	<p>Your verification code for OpenCode Anywhere is:</p>
	<div style="background: #f0f0f0; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 4px; font-weight: bold; margin: 15px 0; border-radius: 5px;">
		%s
	</div>
	<p style="color: #666; font-size: 13px;">This code will expire in 10 minutes. If you did not request this code, please ignore this email.</p>
	<p style="color: #999; font-size: 12px; margin-top: 20px;">OpenCode Anywhere - Remote access for your development environment</p>
</div>
</body>
</html>
	`, code)

	reqBody := resendRequest{
		From:    s.emailFrom,
		To:      []string{to},
		Subject: "OpenCode Anywhere - Verification Code",
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
