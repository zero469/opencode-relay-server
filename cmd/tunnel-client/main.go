package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/skip2/go-qrcode"
	"golang.org/x/term"
)

const (
	configDir        = ".opencode-tunnel"
	authFileName     = "auth.json"
	deviceFileName   = "device.json"
	opencodeFileName = "opencode.json"
	defaultRelay     = "https://opencode-relay.azurewebsites.net"
	defaultPort      = "4096"
	pairingInterval  = 2 * time.Second
)

type AuthConfig struct {
	RelayURL string `json:"relay_url"`
	Token    string `json:"token"`
	Email    string `json:"email"`
}

type DeviceConfig struct {
	DeviceID      int64  `json:"device_id"`
	DeviceName    string `json:"device_name"`
	RelayURL      string `json:"relay_url"`
	Subdomain     string `json:"subdomain"`
	AuthUser      string `json:"auth_user"`
	AuthPassword  string `json:"auth_password"`
	EncryptionKey string `json:"encryption_key,omitempty"`
}

type OpenCodeConfig struct {
	Command   string `json:"command"`
	WorkDir   string `json:"workdir"`
	Port      string `json:"port,omitempty"`
	AutoStart bool   `json:"auto_start"`
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
	Version       int    `json:"v"`
	RelayURL      string `json:"r"`
	PairingID     string `json:"p"`
	PairingCode   string `json:"c"`
	Hostname      string `json:"h,omitempty"`
	EncryptionKey string `json:"k,omitempty"`
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

type SSEEvent struct {
	Type       string          `json:"type"`
	Properties json.RawMessage `json:"properties"`
}

type TunnelEvent struct {
	Event string `json:"event"`
	Data  string `json:"data"`
}

type TunnelClient struct {
	config       *DeviceConfig
	localPort    string
	conn         *websocket.Conn
	writeMu      sync.Mutex
	httpClient   *http.Client
	sseStopChan  chan struct{}
	sseWaitGroup sync.WaitGroup
}

func main() {
	if len(os.Args) < 2 {
		cmdStart()
		return
	}

	switch os.Args[1] {
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
  tunnel-client [command] [options]

Commands:
  start     Start the tunnel (default, can be omitted)
  status    Show current status
  logout    Logout and clear credentials

Options:
  -port <port>   Local OpenCode port (default: 4096)
  -relay <url>   Relay server URL (default: https://opencode-relay.azurewebsites.net)`)
}

func doLogin(relay string) *AuthConfig {
	fmt.Println("\n┌─────────────────────────────────────────────┐")
	fmt.Println("│  Login to OpenCode Relay                    │")
	fmt.Println("└─────────────────────────────────────────────┘")
	fmt.Println()

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

	fmt.Printf("✓ Logged in as %s\n\n", userEmail)
	return auth
}

func cmdStart() {
	localPort := defaultPort
	relay := defaultRelay
	portFromArg := false

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-port":
			if i+1 < len(os.Args) {
				localPort = os.Args[i+1]
				portFromArg = true
				i++
			}
		case "-relay":
			if i+1 < len(os.Args) {
				relay = os.Args[i+1]
				i++
			}
		}
	}

	if !portFromArg {
		if ocConfig, _ := loadOpenCodeConfig(); ocConfig != nil && ocConfig.Port != "" {
			localPort = ocConfig.Port
		}
	}

	ensureOpenCodeRunning(localPort)

	for {
		device, err := loadDeviceConfig()
		if err == nil && device != nil {
			fmt.Printf("  Using device: %s\n", device.DeviceName)
			if runTunnel(device, localPort) {
				return
			}
			fmt.Println("  Connection failed. Re-pairing...")
			clearDeviceConfig()
		}

		auth, err := loadAuthConfig()
		if err != nil {
			auth = doLogin(relay)
		}

		if relay == defaultRelay && auth.RelayURL != "" {
			relay = auth.RelayURL
		}

		device, err = startPairing(relay, auth.Token, localPort)
		if err != nil {
			log.Printf("Pairing failed: %v. Retrying in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		device.RelayURL = relay
		if err := saveDeviceConfig(device); err != nil {
			log.Fatalf("Failed to save device config: %v", err)
		}

		fmt.Printf("\n✓ Device \"%s\" paired successfully!\n", device.DeviceName)

		setupAutoStart(localPort)
	}
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

func ensureOpenCodeRunning(port string) {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://localhost:%s", port)

	resp, err := client.Get(url)
	if err == nil {
		resp.Body.Close()
		return
	}

	fmt.Printf("  OpenCode not detected on port %s\n", port)

	ocConfig, _ := loadOpenCodeConfig()
	if ocConfig != nil && ocConfig.AutoStart && ocConfig.Command != "" {
		fmt.Printf("  Starting OpenCode...\n")
		if startOpenCode(ocConfig, port) {
			return
		}
	}

	configureAndStartOpenCode(port, client)
}

func configureAndStartOpenCode(port string, client *http.Client) {
	command := detectOpenCodeCommand()
	if command == "" {
		fmt.Println("  OpenCode not found. Please enter the command to start it")
		fmt.Print("  (e.g., 'opencode', 'npx opencode'): ")
		fmt.Scanln(&command)
		if command == "" {
			fmt.Println("  Waiting for OpenCode to start manually...")
			waitForOpenCodeManually(port, client)
			return
		}
	}

	cwd, _ := os.Getwd()
	fmt.Printf("  Working directory [%s]: ", cwd)
	var workdir string
	fmt.Scanln(&workdir)
	if workdir == "" {
		workdir = cwd
	}

	if strings.HasPrefix(workdir, "~") {
		home, _ := os.UserHomeDir()
		workdir = filepath.Join(home, strings.TrimPrefix(workdir[1:], "/"))
	}

	if _, err := os.Stat(workdir); os.IsNotExist(err) {
		fmt.Printf("  Directory does not exist: %s\n", workdir)
		fmt.Println("  Waiting for OpenCode to start manually...")
		waitForOpenCodeManually(port, client)
		return
	}

	ocConfig := &OpenCodeConfig{
		Command:   command,
		WorkDir:   workdir,
		Port:      port,
		AutoStart: true,
	}
	saveOpenCodeConfig(ocConfig)

	if !startOpenCode(ocConfig, port) {
		fmt.Println("  Waiting for OpenCode to start manually...")
		waitForOpenCodeManually(port, client)
	}
}

func detectOpenCodeCommand() string {
	commands := []string{"opencode", "npx opencode"}

	for _, cmd := range commands {
		parts := strings.Fields(cmd)
		path, err := exec.LookPath(parts[0])
		if err == nil && path != "" {
			return cmd
		}
	}
	return ""
}

func startOpenCode(config *OpenCodeConfig, port string) bool {
	fmt.Printf("  Starting OpenCode in %s...\n", config.WorkDir)

	parts := strings.Fields(config.Command)
	if len(parts) == 0 {
		return false
	}

	args := parts[1:]
	args = append(args, "--port", port)

	cmd := exec.Command(parts[0], args...)
	cmd.Dir = config.WorkDir
	setProcAttr(cmd)

	logDir := filepath.Join(getConfigDir())
	os.MkdirAll(logDir, 0755)
	logFile, err := os.OpenFile(filepath.Join(logDir, "opencode.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	if err := cmd.Start(); err != nil {
		fmt.Printf("  Failed to start OpenCode: %v\n", err)
		return false
	}

	fmt.Printf("  OpenCode starting (PID: %d)...\n", cmd.Process.Pid)

	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://localhost:%s", port)

	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			fmt.Println("  ✓ OpenCode started successfully!")
			return true
		}
	}

	fmt.Println("  OpenCode did not start in time.")
	return false
}

func waitForOpenCodeManually(port string, client *http.Client) {
	url := fmt.Sprintf("http://localhost:%s", port)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			fmt.Println("✓ OpenCode detected!")
			return
		}
	}
}

func loadOpenCodeConfig() (*OpenCodeConfig, error) {
	path := filepath.Join(getConfigDir(), opencodeFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config OpenCodeConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func saveOpenCodeConfig(config *OpenCodeConfig) error {
	dir := getConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(filepath.Join(dir, opencodeFileName), data, 0600)
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

	hostname, _ := os.Hostname()
	encryptionKey := generateEncryptionKey()

	qrData := QRData{
		Version:       1,
		RelayURL:      relayURL,
		PairingID:     pairing.ID,
		PairingCode:   pairing.PairingCode,
		Hostname:      hostname,
		EncryptionKey: encryptionKey,
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

	device, err := pollPairingStatus(relayURL, token, pairing.ID, pairing.ExpiresAt)
	if err != nil {
		return nil, err
	}
	device.EncryptionKey = encryptionKey
	return device, nil
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

func runTunnel(config *DeviceConfig, localPort string) bool {
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

	return client.connectWithRetry()
}

func (c *TunnelClient) connectWithRetry() bool {
	backoff := time.Second
	maxBackoff := 10 * time.Second

	for {
		err := c.connect()
		if err != nil {
			if isAuthError(err) {
				fmt.Println("\n⚠ Device authentication failed. Device may have been removed.")
				clearDeviceConfig()
				return false
			}

			if isAbnormalClose(err) {
				log.Printf("Connection lost. Reconnecting...")
				backoff = time.Second
			} else {
				log.Printf("Connection error: %v. Retrying in %v...", err, backoff)
				time.Sleep(backoff)
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			continue
		}
		backoff = time.Second
	}
}

func isAbnormalClose(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "1006") ||
		strings.Contains(errStr, "unexpected EOF") ||
		strings.Contains(errStr, "connection reset")
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "Forbidden")
}

func clearDeviceConfig() {
	path := filepath.Join(getConfigDir(), deviceFileName)
	os.Remove(path)
}

func (c *TunnelClient) connect() error {
	wsURL := c.buildWebSocketURL()

	dialer := websocket.Dialer{
		HandshakeTimeout:  10 * time.Second,
		EnableCompression: false,
	}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	c.conn = conn
	defer conn.Close()

	fmt.Printf("✓ Connected! Tunneling to localhost:%s\n", c.localPort)

	conn.SetPongHandler(func(string) error { return nil })

	c.sseStopChan = make(chan struct{})
	c.sseWaitGroup.Add(1)
	go c.subscribeSSE()

	done := make(chan struct{})
	defer func() {
		close(done)
		close(c.sseStopChan)
		c.sseWaitGroup.Wait()
	}()

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

	log.Printf("[debug] WebSocket URL: %s (subdomain: %s)", u.String(), c.config.Subdomain)
	return u.String()
}

func (c *TunnelClient) subscribeSSE() {
	defer c.sseWaitGroup.Done()

	sseURL := fmt.Sprintf("http://localhost:%s/event", c.localPort)
	log.Printf("[SSE] Subscribing to %s", sseURL)

	for {
		select {
		case <-c.sseStopChan:
			log.Printf("[SSE] Stopping subscription")
			return
		default:
		}

		err := c.connectSSE(sseURL)
		if err != nil {
			log.Printf("[SSE] Connection error: %v, reconnecting in 3s...", err)
			select {
			case <-c.sseStopChan:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (c *TunnelClient) connectSSE(sseURL string) error {
	req, err := http.NewRequest("GET", sseURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("SSE returned status %d", resp.StatusCode)
	}

	log.Printf("[SSE] Connected to OpenCode events")

	reader := resp.Body
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)

	for {
		select {
		case <-c.sseStopChan:
			return nil
		default:
		}

		n, err := reader.Read(tmp)
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("SSE connection closed")
			}
			return err
		}

		buf = append(buf, tmp[:n]...)

		for {
			idx := bytes.Index(buf, []byte("\n\n"))
			if idx == -1 {
				break
			}

			eventData := buf[:idx]
			buf = buf[idx+2:]

			c.processSSEEvent(eventData)
		}
	}
}

func (c *TunnelClient) processSSEEvent(eventData []byte) {
	lines := bytes.Split(eventData, []byte("\n"))
	var data []byte

	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimPrefix(line, []byte("data:"))
			data = bytes.TrimSpace(data)
		}
	}

	if len(data) == 0 {
		return
	}

	var raw struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("[SSE] Failed to parse event: %v", err)
		return
	}

	payload := raw.Payload
	if payload == nil {
		payload = data
	}

	var event SSEEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		log.Printf("[SSE] Failed to parse payload: %v", err)
		return
	}

	log.Printf("[SSE] Event: %s", event.Type)

	c.sendEvent(&event)
}

func (c *TunnelClient) sendEvent(event *SSEEvent) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		log.Printf("[SSE] Failed to marshal event: %v", err)
		return
	}

	var tunnelEvent TunnelEvent
	tunnelEvent.Event = "sse"

	if c.config.EncryptionKey != "" {
		encrypted, err := encrypt(eventJSON, c.config.EncryptionKey)
		if err != nil {
			log.Printf("[SSE] Failed to encrypt event: %v", err)
			return
		}
		tunnelEvent.Data = string(encrypted)
	} else {
		tunnelEvent.Data = string(eventJSON)
	}

	data, _ := json.Marshal(tunnelEvent)
	c.writeMu.Lock()
	err = c.conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()

	if err != nil {
		log.Printf("[SSE] Failed to send event: %v", err)
	}
}

func (c *TunnelClient) handleRequest(req *TunnelRequest) {
	log.Printf("[debug] Received request: %s %s", req.Method, req.Path)
	localURL := fmt.Sprintf("http://localhost:%s%s", c.localPort, req.Path)

	requestBody := req.Body
	if c.config.EncryptionKey != "" && len(req.Body) > 0 {
		decrypted, err := decrypt(req.Body, c.config.EncryptionKey)
		if err != nil {
			c.sendErrorResponse(req.ID, 400, "failed to decrypt request")
			return
		}
		requestBody = decrypted
	}

	httpReq, err := http.NewRequest(req.Method, localURL, bytes.NewReader(requestBody))
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

	responseBody := body
	if c.config.EncryptionKey != "" && len(body) > 0 {
		encrypted, err := encrypt(body, c.config.EncryptionKey)
		if err != nil {
			c.sendErrorResponse(req.ID, 500, "failed to encrypt response")
			return
		}
		responseBody = encrypted
	}

	headers := make(map[string]string)
	for key := range resp.Header {
		headers[key] = resp.Header.Get(key)
	}

	headers["Content-Length"] = fmt.Sprintf("%d", len(responseBody))

	// If encrypted, override Content-Type to text/plain so clients don't try to parse as JSON
	if c.config.EncryptionKey != "" {
		headers["Content-Type"] = "text/plain"
	}

	tunnelResp := &TunnelResponse{
		ID:         req.ID,
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       responseBody,
	}

	data, _ := json.Marshal(tunnelResp)
	c.writeMu.Lock()
	err = c.conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()
	if err != nil {
		log.Printf("[debug] Failed to send response: %v", err)
	} else {
		log.Printf("[debug] Sent response: status=%d, bodyLen=%d", resp.StatusCode, len(responseBody))
	}
}

func (c *TunnelClient) sendErrorResponse(reqID string, statusCode int, message string) {
	body := []byte(message)
	if c.config.EncryptionKey != "" {
		encrypted, err := encrypt(body, c.config.EncryptionKey)
		if err == nil {
			body = encrypted
		}
	}

	resp := &TunnelResponse{
		ID:         reqID,
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":   "text/plain",
			"Content-Length": fmt.Sprintf("%d", len(body)),
		},
		Body: body,
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

func setupAutoStart(localPort string) error {
	switch runtime.GOOS {
	case "darwin":
		return setupLaunchd(localPort)
	case "linux":
		return setupSystemd(localPort)
	case "windows":
		return setupWindowsTask(localPort)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func setupLaunchd(localPort string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	launchAgentsDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgentsDir, 0755); err != nil {
		return err
	}

	logDir := filepath.Join(home, ".opencode-relay")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	plistPath := filepath.Join(launchAgentsDir, "com.opencode.relay.plist")
	logPath := filepath.Join(logDir, "tunnel.log")

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.opencode.relay</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>start</string>
        <string>-port</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
</dict>
</plist>
`, execPath, localPort, logPath, logPath)

	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return err
	}

	exec.Command("launchctl", "unload", plistPath).Run()

	cmd := exec.Command("launchctl", "load", plistPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to load launchd plist: %w", err)
	}

	return nil
}

func setupSystemd(localPort string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	systemdDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		return err
	}

	servicePath := filepath.Join(systemdDir, "opencode-relay.service")

	serviceContent := fmt.Sprintf(`[Unit]
Description=OpenCode Relay Tunnel
After=network.target

[Service]
Type=simple
ExecStart=%s start -port %s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, execPath, localPort)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return err
	}

	exec.Command("systemctl", "--user", "daemon-reload").Run()

	cmd := exec.Command("systemctl", "--user", "enable", "opencode-relay.service")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable systemd service: %w", err)
	}

	return nil
}

func setupWindowsTask(localPort string) error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	taskName := "OpenCodeRelay"

	exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()

	cmd := exec.Command("schtasks", "/Create",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`"%s" start -port %s`, execPath, localPort),
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create scheduled task: %w", err)
	}

	return nil
}

func generateEncryptionKey() string {
	key := make([]byte, 32)
	rand.Read(key)
	return hex.EncodeToString(key)
}

func encrypt(plaintext []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func decrypt(ciphertext []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextBytes, nil)
}
