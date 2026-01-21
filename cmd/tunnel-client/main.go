package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

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

type Client struct {
	relayURL     string
	subdomain    string
	authUser     string
	authPassword string
	localPort    string
	conn         *websocket.Conn
	writeMu      sync.Mutex
	httpClient   *http.Client
}

func main() {
	relayURL := flag.String("relay", "", "Relay server URL (e.g., wss://opencode-relay-server.fly.dev)")
	subdomain := flag.String("subdomain", "", "Device subdomain")
	authUser := flag.String("auth-user", "", "Auth username")
	authPassword := flag.String("auth-password", "", "Auth password")
	localPort := flag.String("local-port", "4096", "Local OpenCode port")
	flag.Parse()

	if *relayURL == "" || *subdomain == "" || *authUser == "" || *authPassword == "" {
		fmt.Println("Usage: tunnel-client -relay <url> -subdomain <sub> -auth-user <user> -auth-password <pass> [-local-port <port>]")
		os.Exit(1)
	}

	client := &Client{
		relayURL:     *relayURL,
		subdomain:    *subdomain,
		authUser:     *authUser,
		authPassword: *authPassword,
		localPort:    *localPort,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		if client.conn != nil {
			client.conn.Close()
		}
		os.Exit(0)
	}()

	client.connectWithRetry()
}

func (c *Client) connectWithRetry() {
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

func (c *Client) connect() error {
	wsURL := c.buildWebSocketURL()
	log.Printf("Connecting to %s...", wsURL)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	c.conn = conn
	defer conn.Close()

	log.Printf("Connected! Tunneling to localhost:%s", c.localPort)

	conn.SetPongHandler(func(string) error {
		return nil
	})

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
					log.Printf("Ping failed: %v", err)
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
			log.Printf("Failed to parse request: %v", err)
			continue
		}

		go c.handleRequest(conn, &req)
	}
}

func (c *Client) buildWebSocketURL() string {
	u, _ := url.Parse(c.relayURL)

	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else if u.Scheme == "http" {
		u.Scheme = "ws"
	}

	u.Path = fmt.Sprintf("/api/tunnel/%s", c.subdomain)
	q := u.Query()
	q.Set("auth_user", c.authUser)
	q.Set("auth_password", c.authPassword)
	u.RawQuery = q.Encode()

	return u.String()
}

func (c *Client) handleRequest(conn *websocket.Conn, req *TunnelRequest) {
	localURL := fmt.Sprintf("http://localhost:%s%s", c.localPort, req.Path)

	httpReq, err := http.NewRequest(req.Method, localURL, bytes.NewReader(req.Body))
	if err != nil {
		c.sendErrorResponse(conn, req.ID, 500, "failed to create request")
		return
	}

	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		log.Printf("Local request failed: %v", err)
		c.sendErrorResponse(conn, req.ID, 502, "local service unavailable")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.sendErrorResponse(conn, req.ID, 502, "failed to read response")
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

	data, err := json.Marshal(tunnelResp)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}

	c.writeMu.Lock()
	err = conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()
	if err != nil {
		log.Printf("Failed to send response: %v", err)
	}
}

func (c *Client) sendErrorResponse(conn *websocket.Conn, reqID string, statusCode int, message string) {
	resp := &TunnelResponse{
		ID:         reqID,
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "text/plain"},
		Body:       []byte(message),
	}

	data, _ := json.Marshal(resp)
	c.writeMu.Lock()
	conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()
}
