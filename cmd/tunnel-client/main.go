package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gorilla/websocket"
	"github.com/skip2/go-qrcode"
	"golang.org/x/term"
)

var (
	buildVersion = "dev"
	buildTime    = "unknown"
	buildCommit  = "unknown"
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
	DeviceID      int64  `json:"id"`
	DeviceName    string `json:"name"`
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

type HeartbeatMessage struct {
	Type string `json:"type"`
	Ts   int64  `json:"ts"`
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
	localPort    string                       // default port (for backward compatibility)
	instances    map[string]*OpenCodeInstance // instance_id -> instance (port -> instance for quick lookup)
	instancesMu  sync.RWMutex
	conn         *websocket.Conn
	writeMu      sync.Mutex
	httpClient   *http.Client
	sseStopChan  chan struct{}
	sseWaitGroup sync.WaitGroup
}

// imageCache stores base64 image URLs by partID for lazy loading
var imageCache sync.Map

// dnsCache stores resolved IPs from DNS-over-HTTPS for the process lifetime
var dnsCache sync.Map

// DoH response structures for Cloudflare DNS-over-HTTPS JSON API
type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// debugLogger writes debug/info logs to file only
var debugLogger *log.Logger
var debugLogFile *os.File

func initDebugLogger() {
	dir := getConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	logPath := filepath.Join(dir, "tunnel.log")

	if info, err := os.Stat(logPath); err == nil && info.Size() > 10*1024*1024 {
		os.Remove(logPath)
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	debugLogFile = file
	debugLogger = log.New(file, "", log.LstdFlags)
}

func debugLog(format string, v ...interface{}) {
	if debugLogger != nil {
		debugLogger.Printf(format, v...)
	}
}

func resolveViaDoH(hostname string) (string, error) {
	if cached, ok := dnsCache.Load(hostname); ok {
		return cached.(string), nil
	}

	dohTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, "1.1.1.1:443")
		},
	}
	dohClient := &http.Client{Timeout: 5 * time.Second, Transport: dohTransport}

	dohURL := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", url.QueryEscape(hostname))
	req, err := http.NewRequest("GET", dohURL, nil)
	if err != nil {
		debugLog("[DNS] DoH request creation failed for %s: %v, falling back to system DNS", hostname, err)
		return resolveViaSystemDNS(hostname)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := dohClient.Do(req)
	if err != nil {
		debugLog("[DNS] DoH request failed for %s: %v, falling back to system DNS", hostname, err)
		return resolveViaSystemDNS(hostname)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		debugLog("[DNS] DoH returned status %d for %s, falling back to system DNS", resp.StatusCode, hostname)
		return resolveViaSystemDNS(hostname)
	}

	var dohResp dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
		debugLog("[DNS] DoH response parse failed for %s: %v, falling back to system DNS", hostname, err)
		return resolveViaSystemDNS(hostname)
	}

	for _, answer := range dohResp.Answer {
		if answer.Type == 1 {
			dnsCache.Store(hostname, answer.Data)
			debugLog("[DNS] Resolved %s -> %s via DoH", hostname, answer.Data)
			return answer.Data, nil
		}
	}

	debugLog("[DNS] No A record found via DoH for %s, falling back to system DNS", hostname)
	return resolveViaSystemDNS(hostname)
}

func resolveViaSystemDNS(hostname string) (string, error) {
	debugLog("[DNS] Falling back to system DNS for %s", hostname)
	addrs, err := net.DefaultResolver.LookupHost(context.Background(), hostname)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for %s", hostname)
	}
	dnsCache.Store(hostname, addrs[0])
	return addrs[0], nil
}

func createRelayTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos: []string{"http/1.1"},
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			if host == "127.0.0.1" || host == "localhost" {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			resolvedIP, err := resolveViaDoH(host)
			if err != nil {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
		},
	}
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(0, 2)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("212")).
			Bold(true)

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))
)

type menuModel struct {
	choices  []string
	cursor   int
	auth     *AuthConfig
	device   *DeviceConfig
	selected string
	quitting bool
}

func initialMenu() menuModel {
	auth, _ := loadAuthConfig()
	device, _ := loadDeviceConfig()

	var choices []string
	if auth == nil {
		choices = []string{"Login", "Exit"}
	} else if device == nil {
		choices = []string{"Start Tunnel", "Logout", "Exit"}
	} else {
		choices = []string{"Start Tunnel", "Re-pair Device", "Logout", "Exit"}
	}

	return menuModel{
		choices: choices,
		cursor:  0,
		auth:    auth,
		device:  device,
	}
}

func (m menuModel) Init() tea.Cmd {
	return nil
}

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}
		case "enter":
			m.selected = m.choices[m.cursor]
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m menuModel) View() string {
	var s strings.Builder

	s.WriteString("\n")
	s.WriteString(titleStyle.Render("  OpenCode Anywhere"))
	s.WriteString("\n\n")

	if m.auth != nil {
		s.WriteString(fmt.Sprintf("  Logged in as: %s\n", m.auth.Email))
		if m.device != nil {
			s.WriteString(fmt.Sprintf("  Device: %s ✓\n", m.device.DeviceName))
		} else {
			s.WriteString("  Device: Not paired\n")
		}
	} else {
		s.WriteString("  Not logged in\n")
	}
	s.WriteString("\n")

	for i, choice := range m.choices {
		cursor := "  "
		style := normalStyle
		if m.cursor == i {
			cursor = "> "
			style = selectedStyle
		}
		s.WriteString(cursor + style.Render(choice) + "\n")
	}

	s.WriteString("\n")
	s.WriteString(dimStyle.Render("  (↑/↓ navigate, Enter select, q quit)"))
	s.WriteString("\n")

	return s.String()
}

func runMenu() {
	m := initialMenu()
	p := tea.NewProgram(m)

	finalModel, err := p.Run()
	if err != nil {
		log.Fatalf("Error running menu: %v", err)
	}

	result := finalModel.(menuModel)
	if result.quitting {
		return
	}

	switch result.selected {
	case "Start Tunnel":
		cmdStart()
	case "Login":
		doLogin(defaultRelay)
		runMenu()
	case "Re-pair Device":
		cmdPair()
		cmdStart()
	case "Logout":
		cmdLogout()
		runMenu()
	case "Exit":
		return
	}
}

func main() {
	initDebugLogger()
	if len(os.Args) < 2 {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			runMenu()
		} else {
			cmdStart()
		}
		return
	}

	switch os.Args[1] {
	case "start":
		cmdStart()
	case "status":
		cmdStatus()
	case "logout":
		cmdLogout()
	case "pair":
		cmdPair()
	case "discover":
		cmdDiscover()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`OpenCode Anywhere

Usage:
  tunnel-client [command] [options]

Commands:
  start     Start the tunnel (default, can be omitted)
  pair      Re-pair device (regenerate QR, keep login)
  status    Show current status
  discover  Discover running opencode instances
  logout    Logout and clear credentials

Options:
  -port <port>   Local OpenCode port (default: 4096)
  -relay <url>   Relay server URL (default: https://opencode-relay.victoriouswater-fc24e366.eastasia.azurecontainerapps.io)`)
}

func doLogin(relay string) *AuthConfig {
	fmt.Println("\n┌─────────────────────────────────────────────┐")
	fmt.Println("│  Login to OpenCode Anywhere                 │")
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
	fmt.Printf("tunnel-client %s (built: %s, commit: %s)\n", buildVersion, buildTime, buildCommit)

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
			fmt.Printf("  Connecting to relay server...\n")
			if runTunnel(device, localPort) {
				return
			}
			fmt.Println()
			fmt.Println("  ⚠ Connection failed. This could be because:")
			fmt.Println("    - The device was deleted from your account")
			fmt.Println("    - Network connectivity issues")
			fmt.Println("    - The relay server is temporarily unavailable")
			fmt.Println()
			fmt.Println("  Clearing old device config and starting fresh pairing...")
			fmt.Println()
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
			if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "unauthorized") {
				fmt.Println("  Session expired. Please login again.")
				clearAuthConfig()
				continue
			}
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

func cmdPair() {
	relay := defaultRelay
	localPort := defaultPort

	for i := 1; i < len(os.Args); i++ {
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

	auth, err := loadAuthConfig()
	if err != nil {
		auth = doLogin(relay)
	}

	if relay == defaultRelay && auth.RelayURL != "" {
		relay = auth.RelayURL
	}

	clearDeviceConfig()

	device, err := startPairing(relay, auth.Token, localPort)
	if err != nil {
		log.Fatalf("Pairing failed: %v", err)
	}

	device.RelayURL = relay
	if err := saveDeviceConfig(device); err != nil {
		log.Fatalf("Failed to save device config: %v", err)
	}

	fmt.Printf("\n✓ Device \"%s\" paired successfully!\n", device.DeviceName)
	setupAutoStart(localPort)
}

func ensureOpenCodeRunning(port string) {
	client := &http.Client{Timeout: 2 * time.Second}
	// Use 127.0.0.1 instead of localhost to avoid IPv6 timeout issues
	url := fmt.Sprintf("http://127.0.0.1:%s", port)

	// Retry up to 3 times with 1 second interval
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			debugLog("[detection] OpenCode detected on port %s (attempt %d)", port, attempt)
			return
		}

		debugLog("[detection] Attempt %d: failed to reach %s: %v", attempt, url, err)

		if attempt < 3 {
			time.Sleep(1 * time.Second)
		}
	}

	// HTTP detection failed, check if opencode process is running
	if pids := getOpenCodePIDs(); len(pids) > 0 {
		debugLog("[detection] HTTP check failed but opencode process found: PIDs %v", pids)
		fmt.Printf("  OpenCode process found (PID: %s), waiting for port %s...\n", strings.Join(pids, ", "), port)
		// Wait for port to be ready (up to 30 seconds)
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Second)
			resp, err := client.Get(url)
			if err == nil {
				resp.Body.Close()
				fmt.Printf("  ✓ OpenCode is ready on port %s\n", port)
				return
			}
		}
		fmt.Printf("  OpenCode process exists but port %s not responding\n", port)
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

func getOpenCodePIDs() []string {
	var pids []string

	if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq opencode.exe", "/FO", "CSV", "/NH")
		output, err := cmd.Output()
		if err != nil {
			return nil
		}
		// Parse CSV output: "opencode.exe","1234",...
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				pid := strings.Trim(parts[1], "\"")
				pids = append(pids, pid)
			}
		}
	} else {
		// Use ps + grep for cross-platform compatibility (pgrep behaves differently on macOS)
		cmd := exec.Command("sh", "-c", "ps -eo pid,comm | grep '[o]pencode$' | awk '{print $1}'")
		output, err := cmd.Output()
		if err != nil {
			return nil
		}
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if pid := strings.TrimSpace(line); pid != "" {
				pids = append(pids, pid)
			}
		}
	}

	return pids
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

	// Reap the child process to prevent zombies
	go func() {
		cmd.Wait()
		if logFile != nil {
			logFile.Close()
		}
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%s", port)

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
	url := fmt.Sprintf("http://127.0.0.1:%s", port)
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

	client := &http.Client{Timeout: 10 * time.Second, Transport: createRelayTransport()}
	resp, err := client.Post(relayURL+"/api/login", "application/json", bytes.NewReader(body))
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

	client := &http.Client{Timeout: 10 * time.Second, Transport: createRelayTransport()}
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
	client := &http.Client{Timeout: 10 * time.Second, Transport: createRelayTransport()}

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
	if !verifyDeviceWithServer(config) {
		fmt.Println("\n⚠ Device verification failed. Device may have been removed or credentials are invalid.")
		fmt.Println("  Please re-pair your device.")
		clearDeviceConfig()
		return false
	}

	client := &TunnelClient{
		config:    config,
		localPort: localPort,
		instances: make(map[string]*OpenCodeInstance),
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}

	client.refreshInstances()

	go client.instanceRefreshLoop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v (PID: %d)", sig, os.Getpid())
		fmt.Printf("\nShutting down due to signal: %v...\n", sig)
		if client.conn != nil {
			client.conn.Close()
		}
		os.Exit(0)
	}()

	return client.connectWithRetry()
}

func (c *TunnelClient) refreshInstances() {
	instances := discoverOpenCodeInstances()

	c.instancesMu.Lock()
	defer c.instancesMu.Unlock()

	c.instances = make(map[string]*OpenCodeInstance)
	for i := range instances {
		inst := &instances[i]
		if inst.Port != "" && inst.Healthy {
			c.instances[inst.Port] = inst
			debugLog("[instances] Registered instance: port=%s dir=%s", inst.Port, inst.Dir)
		}
	}

	debugLog("[instances] Total healthy instances: %d", len(c.instances))
}

func (c *TunnelClient) instanceRefreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.refreshInstances()
	}
}

func verifyDeviceWithServer(config *DeviceConfig) bool {
	reqBody, _ := json.Marshal(map[string]string{
		"subdomain":     config.Subdomain,
		"auth_user":     config.AuthUser,
		"auth_password": config.AuthPassword,
	})

	client := &http.Client{Timeout: 10 * time.Second, Transport: createRelayTransport()}
	resp, err := client.Post(config.RelayURL+"/api/device/verify", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		debugLog("[verify] Request failed: %v, proceeding anyway", err)
		return true
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		debugLog("[verify] Device verified successfully")
		return true
	}

	body, _ := io.ReadAll(resp.Body)
	debugLog("[verify] Device verification failed: status=%d, body=%s", resp.StatusCode, string(body))

	if resp.StatusCode == 404 || resp.StatusCode == 401 {
		return false
	}

	return true
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
	// Check for HTTP status codes in error
	if strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "404") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "Forbidden") {
		return true
	}
	// Check for bad handshake which happens when server rejects before upgrade
	// This indicates auth/device validation failed
	if strings.Contains(errStr, "bad handshake") {
		return true
	}
	return false
}

func clearDeviceConfig() {
	path := filepath.Join(getConfigDir(), deviceFileName)
	os.Remove(path)
}

func clearAuthConfig() {
	path := filepath.Join(getConfigDir(), authFileName)
	os.Remove(path)
}

func (c *TunnelClient) connect() error {
	wsURL := c.buildWebSocketURL()

	dialer := websocket.Dialer{
		HandshakeTimeout:  10 * time.Second,
		EnableCompression: false,
		TLSClientConfig: &tls.Config{
			NextProtos: []string{"http/1.1"}, // Force HTTP/1.1, avoid HTTP/2 (Azure ALPN issue)
		},
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			if host == "127.0.0.1" || host == "localhost" {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			resolvedIP, err := resolveViaDoH(host)
			if err != nil {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
		},
	}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	c.conn = conn
	defer conn.Close()

	fmt.Printf("✓ Connected! Tunneling to localhost:%s\n", c.localPort)

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

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
		ticker := time.NewTicker(10 * time.Second)
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
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, message, err := conn.ReadMessage()
		if err != nil {
			// Log the specific error type for debugging
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("[WebSocket] Connection closed normally: %v", err)
			} else if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("[WebSocket] Unexpected close: %v", err)
			} else {
				log.Printf("[WebSocket] Read error: %v", err)
			}
			return fmt.Errorf("read error: %w", err)
		}

		var heartbeat HeartbeatMessage
		if err := json.Unmarshal(message, &heartbeat); err == nil && heartbeat.Type == "heartbeat" {
			debugLog("[heartbeat] Received heartbeat ts=%d", heartbeat.Ts)
			ack := HeartbeatMessage{
				Type: "heartbeat_ack",
				Ts:   heartbeat.Ts,
			}
			ackData, _ := json.Marshal(ack)
			c.writeMu.Lock()
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := conn.WriteMessage(websocket.TextMessage, ackData)
			c.writeMu.Unlock()
			if err != nil {
				log.Printf("[heartbeat] Failed to send heartbeat_ack: %v", err)
			} else {
				debugLog("[heartbeat] Sent heartbeat_ack ts=%d", heartbeat.Ts)
			}
			continue
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

	debugLog("[debug] WebSocket URL: %s (subdomain: %s)", u.String(), c.config.Subdomain)
	return u.String()
}

func (c *TunnelClient) subscribeSSE() {
	defer c.sseWaitGroup.Done()

	sseURL := fmt.Sprintf("http://127.0.0.1:%s/event", c.localPort)
	debugLog("[SSE] Subscribing to %s", sseURL)

	for {
		select {
		case <-c.sseStopChan:
			debugLog("[SSE] Stopping subscription")
			return
		default:
		}

		err := c.connectSSE(sseURL)
		if err != nil {
			debugLog("[SSE] Connection error: %v, reconnecting in 3s...", err)
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

	debugLog("[SSE] Connected to OpenCode events")

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
		debugLog("[SSE] Failed to parse event: %v", err)
		return
	}

	payload := raw.Payload
	if payload == nil {
		payload = data
	}

	var event SSEEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		debugLog("[SSE] Failed to parse payload: %v", err)
		return
	}

	debugLog("[SSE] Event: %s", event.Type)

	c.sendEvent(&event)
}

func (c *TunnelClient) sendEvent(event *SSEEvent) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		debugLog("[SSE] Failed to marshal event: %v", err)
		return
	}

	var tunnelEvent TunnelEvent
	tunnelEvent.Event = "sse"

	if c.config.EncryptionKey != "" {
		encrypted, err := encrypt(eventJSON, c.config.EncryptionKey)
		if err != nil {
			debugLog("[SSE] Failed to encrypt event: %v", err)
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
		debugLog("[SSE] Failed to send event: %v", err)
	}
}

func (c *TunnelClient) handleRequest(req *TunnelRequest) {
	debugLog("[debug] Received request: %s %s", req.Method, req.Path)
	if strings.Contains(req.Path, "prompt_async") && len(req.Body) > 0 {
		debugLog("[debug] Request body (first 500 chars): %s", string(req.Body[:min(len(req.Body), 500)]))
	}

	if req.Path == "/discover" || req.Path == "/discover/" {
		c.handleDiscover(req)
		return
	}

	if strings.HasPrefix(req.Path, "/lazy-image/") {
		c.handleLazyImage(req)
		return
	}

	targetPort := c.localPort
	targetPath := req.Path

	if strings.HasPrefix(req.Path, "/i/") {
		parts := strings.SplitN(strings.TrimPrefix(req.Path, "/i/"), "/", 2)
		if len(parts) >= 1 && parts[0] != "" {
			instanceID := parts[0]
			c.instancesMu.RLock()
			inst, exists := c.instances[instanceID]
			c.instancesMu.RUnlock()

			if exists {
				targetPort = inst.Port
				if len(parts) > 1 {
					targetPath = "/" + parts[1]
				} else {
					targetPath = "/"
				}
				debugLog("[debug] Routing to instance %s (port %s): %s", instanceID, targetPort, targetPath)
			} else {
				c.sendErrorResponse(req.ID, 404, fmt.Sprintf(`{"error":"instance_not_found","instance_id":"%s"}`, instanceID))
				return
			}
		}
	}

	localURL := fmt.Sprintf("http://127.0.0.1:%s%s", targetPort, targetPath)

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

	originalSize := len(body)
	start := time.Now()
	if strippedBody, stripped := stripBase64Images(body, req.Path); stripped {
		body = strippedBody
		debugLog("[debug] Stripped images in %dms, size reduced from %d to %d bytes",
			time.Since(start).Milliseconds(), originalSize, len(body))
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
		debugLog("[debug] Failed to send response: %v", err)
	} else {
		debugLog("[debug] Sent response: status=%d, bodyLen=%d", resp.StatusCode, len(responseBody))
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

func (c *TunnelClient) handleLazyImage(req *TunnelRequest) {
	partID := strings.TrimPrefix(req.Path, "/lazy-image/")

	url, ok := imageCache.Load(partID)
	if !ok {
		debugLog("[debug] Image not found in cache for partID: %s", partID)
		c.sendErrorResponse(req.ID, 404, `{"error": "not found"}`)
		return
	}

	debugLog("[debug] Serving cached image for partID: %s", partID)

	responseJSON, _ := json.Marshal(map[string]string{"url": url.(string)})

	responseBody := responseJSON
	if c.config.EncryptionKey != "" {
		encrypted, err := encrypt(responseJSON, c.config.EncryptionKey)
		if err != nil {
			c.sendErrorResponse(req.ID, 500, "failed to encrypt response")
			return
		}
		responseBody = encrypted
	}

	contentType := "application/json"
	if c.config.EncryptionKey != "" {
		contentType = "text/plain"
	}

	tunnelResp := &TunnelResponse{
		ID:         req.ID,
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":   contentType,
			"Content-Length": fmt.Sprintf("%d", len(responseBody)),
		},
		Body: responseBody,
	}

	data, _ := json.Marshal(tunnelResp)
	c.writeMu.Lock()
	err := c.conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()
	if err != nil {
		debugLog("[debug] Failed to send lazy-image response: %v", err)
	}
}

type DiscoverResponse struct {
	Instances []InstanceInfo `json:"instances"`
}

type InstanceInfo struct {
	ID      string `json:"id"`
	Port    string `json:"port"`
	Dir     string `json:"dir"`
	Healthy bool   `json:"healthy"`
}

func (c *TunnelClient) handleDiscover(req *TunnelRequest) {
	c.instancesMu.RLock()
	instances := make([]InstanceInfo, 0, len(c.instances))
	for _, inst := range c.instances {
		instances = append(instances, InstanceInfo{
			ID:      inst.Port,
			Port:    inst.Port,
			Dir:     inst.Dir,
			Healthy: inst.Healthy,
		})
	}
	c.instancesMu.RUnlock()

	response := DiscoverResponse{Instances: instances}
	responseJSON, _ := json.Marshal(response)

	responseBody := responseJSON
	if c.config.EncryptionKey != "" {
		encrypted, err := encrypt(responseJSON, c.config.EncryptionKey)
		if err != nil {
			c.sendErrorResponse(req.ID, 500, "failed to encrypt response")
			return
		}
		responseBody = encrypted
	}

	contentType := "application/json"
	if c.config.EncryptionKey != "" {
		contentType = "text/plain"
	}

	tunnelResp := &TunnelResponse{
		ID:         req.ID,
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":   contentType,
			"Content-Length": fmt.Sprintf("%d", len(responseBody)),
		},
		Body: responseBody,
	}

	data, _ := json.Marshal(tunnelResp)
	c.writeMu.Lock()
	err := c.conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()
	if err != nil {
		debugLog("[debug] Failed to send discover response: %v", err)
	}
}

// stripBase64Images strips base64 image data from message list responses
// and replaces them with lazy:{partID} placeholders for on-demand loading.
func stripBase64Images(body []byte, path string) ([]byte, bool) {
	// Only process message list endpoint (with or without query params)
	matched, _ := regexp.MatchString(`^/session/[^/]+/message(\?.*)?$`, path)
	if !matched {
		return body, false
	}

	// Parse JSON as array of messages
	var messages []map[string]interface{}
	if err := json.Unmarshal(body, &messages); err != nil {
		return body, false // Not valid JSON array, return unchanged
	}

	modified := false
	for _, msg := range messages {
		parts, ok := msg["parts"].([]interface{})
		if !ok {
			continue
		}
		for _, p := range parts {
			part, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if part["type"] == "file" {
				url, _ := part["url"].(string)
				if strings.HasPrefix(url, "data:image/") {
					partID, _ := part["id"].(string)
					imageCache.Store(partID, url)
					debugLog("[debug] Cached image for partID: %s (size: %d)", partID, len(url))
					part["url"] = "lazy:" + partID
					modified = true
				}
			}
		}
	}

	if !modified {
		return body, false
	}

	newBody, err := json.Marshal(messages)
	if err != nil {
		return body, false
	}
	return newBody, true
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
	if config.Subdomain == "" || config.AuthUser == "" || config.AuthPassword == "" {
		return nil, fmt.Errorf("incomplete device config")
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
Description=OpenCode Anywhere Tunnel
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

// OpenCodeInstance represents a discovered opencode instance
type OpenCodeInstance struct {
	PID     string
	Port    string
	Dir     string
	Healthy bool
}

// cmdDiscover discovers all running opencode instances
func cmdDiscover() {
	fmt.Println("\n┌─────────────────────────────────────────────┐")
	fmt.Println("│  OpenCode Instance Discovery                │")
	fmt.Println("└─────────────────────────────────────────────┘")
	fmt.Println()

	instances := discoverOpenCodeInstances()

	var servers []OpenCodeInstance
	for _, inst := range instances {
		if inst.Port != "" {
			servers = append(servers, inst)
		}
	}

	if len(servers) == 0 {
		fmt.Println("  No opencode servers found.")
		fmt.Println()
		if len(instances) > 0 {
			fmt.Printf("  (Found %d opencode process(es) without listening ports)\n", len(instances))
		}
		fmt.Println()
		fmt.Println("  Tips:")
		fmt.Println("  - Make sure opencode is running (run 'opencode' in a project directory)")
		fmt.Println("  - Check if the server has started (wait a few seconds)")
		return
	}

	fmt.Printf("  Found %d opencode server(s):\n\n", len(servers))

	for i, inst := range servers {
		status := "✓ healthy"
		if !inst.Healthy {
			status = "✗ unreachable"
		}
		fmt.Printf("  %d. %s\n", i+1, status)
		fmt.Printf("     PID:  %s\n", inst.PID)
		fmt.Printf("     Port: %s\n", inst.Port)
		fmt.Printf("     Dir:  %s\n", inst.Dir)
		fmt.Println()
	}

	if len(instances) > len(servers) {
		fmt.Printf("  (Also found %d opencode process(es) without listening ports)\n", len(instances)-len(servers))
	}
}

// discoverOpenCodeInstances finds all running opencode instances with their ports and directories
func discoverOpenCodeInstances() []OpenCodeInstance {
	pids := getOpenCodePIDs()
	if len(pids) == 0 {
		return nil
	}

	debugLog("[discover] Found %d opencode PIDs: %v", len(pids), pids)

	pidSet := make(map[string]bool)
	for _, pid := range pids {
		pidSet[pid] = true
	}

	portMap := getOpenCodeListeningPorts(pidSet)
	cwdMap := getOpenCodeCwds(pids)

	var instances []OpenCodeInstance
	for _, pid := range pids {
		inst := OpenCodeInstance{
			PID:  pid,
			Port: portMap[pid],
			Dir:  cwdMap[pid],
		}

		if inst.Port != "" {
			inst.Healthy = checkOpenCodeHealth(inst.Port)
		}

		instances = append(instances, inst)
	}

	return instances
}

func getOpenCodeListeningPorts(pidSet map[string]bool) map[string]string {
	result := make(map[string]string)

	if runtime.GOOS == "windows" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "cmd", "/c", "netstat -ano | findstr LISTENING")
		output, err := cmd.Output()
		if err != nil {
			debugLog("[discover] netstat failed: %v", err)
			return result
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			pid := fields[len(fields)-1]
			if !pidSet[pid] {
				continue
			}
			addr := fields[1]
			parts := strings.Split(addr, ":")
			if len(parts) >= 2 {
				result[pid] = parts[len(parts)-1]
			}
		}
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lsof", "-i", "-P", "-n")
	output, err := cmd.Output()
	if err != nil {
		debugLog("[discover] lsof -i failed: %v", err)
		return result
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[0] != "opencode" {
			continue
		}
		pid := fields[1]
		if !pidSet[pid] {
			continue
		}
		addr := fields[8]
		parts := strings.Split(addr, ":")
		if len(parts) >= 2 {
			result[pid] = parts[len(parts)-1]
		}
	}

	return result
}

func getOpenCodeCwds(pids []string) map[string]string {
	result := make(map[string]string)

	if runtime.GOOS == "windows" {
		for _, pid := range pids {
			if cwd := getProcessCwdWindows(pid); cwd != "" {
				result[pid] = cwd
			}
		}
		return result
	}

	if runtime.GOOS == "linux" {
		for _, pid := range pids {
			cwdLink := fmt.Sprintf("/proc/%s/cwd", pid)
			if cwd, err := os.Readlink(cwdLink); err == nil {
				result[pid] = cwd
			}
		}
		return result
	}

	for _, pid := range pids {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, "lsof", "-a", "-d", "cwd", "-p", pid, "-Fn")
		output, err := cmd.Output()
		cancel()
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "n") {
				result[pid] = line[1:]
				break
			}
		}
	}

	return result
}

// getProcessCwdWindows gets cwd on Windows (limited support)
func getProcessCwdWindows(pid string) string {
	debugLog("[discover] Windows CWD detection not implemented for PID %s", pid)
	return "(not available on Windows)"
}

// checkOpenCodeHealth verifies if an opencode instance is responding
func checkOpenCodeHealth(port string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	url := fmt.Sprintf("http://127.0.0.1:%s", port)

	resp, err := client.Get(url)
	if err != nil {
		debugLog("[discover] health check failed for port %s: %v", port, err)
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}
