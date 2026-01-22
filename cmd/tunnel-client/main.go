package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/skip2/go-qrcode"
	"golang.org/x/term"
)

const (
	configDir       = ".opencode-tunnel"
	authFileName    = "auth.json"
	deviceFileName  = "device.json"
	defaultRelay    = "https://opencode-relay.azurewebsites.net"
	defaultPort     = "4096"
	pairingInterval = 2 * time.Second
)

type AuthConfig struct {
	RelayURL string `json:"relay_url"`
	Token    string `json:"token"`
	Email    string `json:"email"`
}

type DeviceConfig struct {
	DeviceID     int64  `json:"device_id"`
	DeviceName   string `json:"device_name"`
	RelayURL     string `json:"relay_url"`
	Subdomain    string `json:"subdomain"`
	AuthUser     string `json:"auth_user"`
	AuthPassword string `json:"auth_password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

type PairingResponse struct {
	ID          string    `json:"id"`
	PairingCode string    `json:"pairing_code"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type PairingStatusResponse struct {
	Status string        `json:"status"`
	Device *DeviceConfig `json:"device,omitempty"`
}

type QRData struct {
	Version     int    `json:"v"`
	RelayURL    string `json:"r"`
	PairingID   string `json:"p"`
	PairingCode string `json:"c"`
}

type TunnelRequest struct {
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

type TunnelResponse struct {
	ID         string            `json:"id"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
}

type TunnelClient struct {
	config     *DeviceConfig
	localPort  string
	conn       *websocket.Conn
	writeMu    sync.Mutex
	httpClient *http.Client
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "login":
		cmdLogin()
	case "start":
		cmdStart()
	case "status":
		cmdStatus()
	case "logout":
		cmdLogout()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`OpenCode Tunnel Client

Usage:
  tunnel-client <command> [options]

Commands:
  login     Login with your account
  start     Start the tunnel (will show QR code if not paired)
  status    Show current status
  logout    Logout and clear credentials

Options for 'start':
  -port <port>   Local OpenCode port (default: 4096)
  -relay <url>   Relay server URL (default: https://opencode-relay.azurewebsites.net)`)
}

func cmdLogin() {
	relay := defaultRelay
	if len(os.Args) > 2 {
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "-relay" && i+1 < len(os.Args) {
				relay = os.Args[i+1]
				i++
			}
		}
	}

	fmt.Print("Email: ")
	var email string
	fmt.Scanln(&email)

	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	password := string(passwordBytes)

	token, userEmail, err := login(relay, email, password)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	auth := &AuthConfig{
		RelayURL: relay,
		Token:    token,
		Email:    userEmail,
	}
	if err := saveAuthConfig(auth); err != nil {
		log.Fatalf("Failed to save credentials: %v", err)
	}

	fmt.Printf("✓ Logged in as %s\n", userEmail)
}

func cmdStart() {
	localPort := defaultPort
	relay := ""

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-port":
			if i+1 < len(os.Args) {
				localPort = os.Args[i+1]
				i++
			}
		case "-relay":
			if i+1 < len(os.Args) {
				relay = os.Args[i+1]
				i++
			}
		}
	}

	device, err := loadDeviceConfig()
	if err == nil && device != nil {
		runTunnel(device, localPort)
		return
	}

	auth, err := loadAuthConfig()
	if err != nil {
		fmt.Println("Not logged in. Please run: tunnel-client login")
		os.Exit(1)
	}

	if relay == "" {
		relay = auth.RelayURL
	}

	device, err = startPairing(relay, auth.Token, localPort)
	if err != nil {
		log.Fatalf("Pairing failed: %v", err)
	}

	device.RelayURL = relay
	if err := saveDeviceConfig(device); err != nil {
		log.Fatalf("Failed to save device config: %v", err)
	}

	fmt.Printf("\n✓ Device \"%s\" paired successfully!\n", device.DeviceName)
	fmt.Println("✓ Starting tunnel...")

	runTunnel(device, localPort)
}

func cmdStatus() {
	auth, authErr := loadAuthConfig()
	device, deviceErr := loadDeviceConfig()

	if authErr != nil && deviceErr != nil {
		fmt.Println("Not logged in")
		return
	}

	if auth != nil {
		fmt.Printf("Logged in as: %s\n", auth.Email)
		fmt.Printf("Relay: %s\n", auth.RelayURL)
	}

	if device != nil {
		fmt.Printf("\nDevice: %s\n", device.DeviceName)
		fmt.Printf("Subdomain: %s\n", device.Subdomain)
	} else {
		fmt.Println("\nNo device paired")
	}
}

func cmdLogout() {
	configPath := getConfigDir()

	authPath := filepath.Join(configPath, authFileName)
	os.Remove(authPath)

	devicePath := filepath.Join(configPath, deviceFileName)
	os.Remove(devicePath)

	fmt.Println("✓ Logged out")
}

func login(relayURL, email, password string) (string, string, error) {
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	resp, err := http.Post(relayURL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("login failed: %s", string(bodyBytes))
	}

	var result LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	return result.Token, result.User.Email, nil
}

func startPairing(relayURL, token, localPort string) (*DeviceConfig, error) {
	req, _ := http.NewRequest("POST", relayURL+"/api/pairing", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create pairing: %s", string(bodyBytes))
	}

	var pairing PairingResponse
	if err := json.NewDecoder(resp.Body).Decode(&pairing); err != nil {
		return nil, err
	}

	qrData := QRData{
		Version:     1,
		RelayURL:    relayURL,
		PairingID:   pairing.ID,
		PairingCode: pairing.PairingCode,
	}
	qrJSON, _ := json.Marshal(qrData)

	qr, err := qrcode.New(string(qrJSON), qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	fmt.Println("\n┌─────────────────────────────────────────────┐")
	fmt.Println("│  Scan this QR code with the OpenCode App    │")
	fmt.Println("└─────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println(qr.ToSmallString(false))
	fmt.Printf("  Pairing code: %s\n", pairing.PairingCode)
	fmt.Printf("  Expires at: %s\n\n", pairing.ExpiresAt.Local().Format("15:04:05"))
	fmt.Println("  Waiting for app to scan...")

	return pollPairingStatus(relayURL, token, pairing.ID, pairing.ExpiresAt)
}

func pollPairingStatus(relayURL, token, pairingID string, expiresAt time.Time) (*DeviceConfig, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		if time.Now().After(expiresAt) {
			return nil, fmt.Errorf("pairing expired")
		}

		req, _ := http.NewRequest("GET", relayURL+"/api/pairing/"+pairingID+"/status", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(pairingInterval)
			continue
		}

		var status PairingStatusResponse
		json.NewDecoder(resp.Body).Decode(&status)
		resp.Body.Close()

		switch status.Status {
		case "completed":
			if status.Device != nil {
				return status.Device, nil
			}
			return nil, fmt.Errorf("pairing completed but no device info")
		case "expired":
			return nil, fmt.Errorf("pairing expired")
		}

		time.Sleep(pairingInterval)
	}
}

func runTunnel(config *DeviceConfig, localPort string) {
	client := &TunnelClient{
		config:    config,
		localPort: localPort,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		if client.conn != nil {
			client.conn.Close()
		}
		os.Exit(0)
	}()

	client.connectWithRetry()
}

func (c *TunnelClient) connectWithRetry() {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		err := c.connect()
		if err != nil {
			log.Printf("Connection error: %v. Retrying in %v...", err, backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second
	}
}

func (c *TunnelClient) connect() error {
	wsURL := c.buildWebSocketURL()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	c.conn = conn
	defer conn.Close()

	fmt.Printf("✓ Connected! Tunneling to localhost:%s\n", c.localPort)

	conn.SetPongHandler(func(string) error { return nil })

	done := make(chan struct{})
	defer close(done)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.writeMu.Lock()
				err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
				c.writeMu.Unlock()
				if err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read error: %w", err)
		}

		var req TunnelRequest
		if err := json.Unmarshal(message, &req); err != nil {
			continue
		}

		go c.handleRequest(&req)
	}
}

func (c *TunnelClient) buildWebSocketURL() string {
	u, _ := url.Parse(c.config.RelayURL)

	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else if u.Scheme == "http" {
		u.Scheme = "ws"
	}

	u.Path = fmt.Sprintf("/api/tunnel/%s", c.config.Subdomain)
	q := u.Query()
	q.Set("auth_user", c.config.AuthUser)
	q.Set("auth_password", c.config.AuthPassword)
	u.RawQuery = q.Encode()

	return u.String()
}

func (c *TunnelClient) handleRequest(req *TunnelRequest) {
	localURL := fmt.Sprintf("http://localhost:%s%s", c.localPort, req.Path)

	httpReq, err := http.NewRequest(req.Method, localURL, bytes.NewReader(req.Body))
	if err != nil {
		c.sendErrorResponse(req.ID, 500, "failed to create request")
		return
	}

	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		c.sendErrorResponse(req.ID, 502, "local service unavailable")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.sendErrorResponse(req.ID, 502, "failed to read response")
		return
	}

	headers := make(map[string]string)
	for key := range resp.Header {
		headers[key] = resp.Header.Get(key)
	}

	tunnelResp := &TunnelResponse{
		ID:         req.ID,
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
	}

	data, _ := json.Marshal(tunnelResp)
	c.writeMu.Lock()
	c.conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()
}

func (c *TunnelClient) sendErrorResponse(reqID string, statusCode int, message string) {
	resp := &TunnelResponse{
		ID:         reqID,
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "text/plain"},
		Body:       []byte(message),
	}

	data, _ := json.Marshal(resp)
	c.writeMu.Lock()
	c.conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()
}

func getConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, configDir)
}

func loadAuthConfig() (*AuthConfig, error) {
	path := filepath.Join(getConfigDir(), authFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config AuthConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func saveAuthConfig(config *AuthConfig) error {
	dir := getConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(filepath.Join(dir, authFileName), data, 0600)
}

func loadDeviceConfig() (*DeviceConfig, error) {
	path := filepath.Join(getConfigDir(), deviceFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config DeviceConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func saveDeviceConfig(config *DeviceConfig) error {
	dir := getConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(filepath.Join(dir, deviceFileName), data, 0600)
}
