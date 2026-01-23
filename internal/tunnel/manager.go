package tunnel

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	ErrTunnelNotFound = errors.New("tunnel not found")
	ErrTunnelTimeout  = errors.New("tunnel request timeout")
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

type TunnelEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

type TunnelConnection struct {
	conn      *websocket.Conn
	subdomain string
	pending   map[string]chan *TunnelResponse
	pendingMu sync.RWMutex
	writeMu   sync.Mutex
	closeChan chan struct{}
	closeOnce sync.Once
	replaced  bool
}

type EventClient struct {
	conn      *websocket.Conn
	subdomain string
	closeChan chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex
}

type Manager struct {
	connections  map[string]*TunnelConnection
	eventClients map[string]map[*EventClient]struct{}
	mu           sync.RWMutex
	upgrader     websocket.Upgrader
	onHeartbeat  func(subdomain string)
	onDisconnect func(subdomain string)
}

func NewManager() *Manager {
	return &Manager{
		connections:  make(map[string]*TunnelConnection),
		eventClients: make(map[string]map[*EventClient]struct{}),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
			ReadBufferSize:    1024 * 64,
			WriteBufferSize:   1024 * 64,
			EnableCompression: false,
		},
	}
}

func (m *Manager) SetCallbacks(onHeartbeat, onDisconnect func(subdomain string)) {
	m.onHeartbeat = onHeartbeat
	m.onDisconnect = onDisconnect
}

func (m *Manager) HandleWebSocket(w http.ResponseWriter, r *http.Request, subdomain string) error {
	conn, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}

	tc := &TunnelConnection{
		conn:      conn,
		subdomain: subdomain,
		pending:   make(map[string]chan *TunnelResponse),
		closeChan: make(chan struct{}),
	}

	m.mu.Lock()
	if existing, ok := m.connections[subdomain]; ok {
		existing.replaced = true
		existing.Close()
	}
	m.connections[subdomain] = tc
	m.mu.Unlock()

	log.Printf("[tunnel] Client connected: %s", subdomain)

	if m.onHeartbeat != nil {
		m.onHeartbeat(subdomain)
	}

	go tc.readLoop(m)
	go tc.pingLoop(m)

	return nil
}

func (m *Manager) ForwardRequest(subdomain string, req *TunnelRequest) (*TunnelResponse, error) {
	m.mu.RLock()
	tc, ok := m.connections[subdomain]
	m.mu.RUnlock()

	if !ok {
		return nil, ErrTunnelNotFound
	}

	return tc.SendRequest(req)
}

func (m *Manager) IsConnected(subdomain string) bool {
	m.mu.RLock()
	_, ok := m.connections[subdomain]
	m.mu.RUnlock()
	return ok
}

func (m *Manager) removeConnection(tc *TunnelConnection) {
	m.mu.Lock()
	current, ok := m.connections[tc.subdomain]
	if ok && current == tc {
		delete(m.connections, tc.subdomain)
	}
	m.mu.Unlock()

	if tc.replaced {
		log.Printf("[tunnel] Client replaced: %s (skipping disconnect callback)", tc.subdomain)
		return
	}

	log.Printf("[tunnel] Client disconnected: %s", tc.subdomain)

	if m.onDisconnect != nil {
		m.onDisconnect(tc.subdomain)
	}
}

func (tc *TunnelConnection) SendRequest(req *TunnelRequest) (*TunnelResponse, error) {
	respChan := make(chan *TunnelResponse, 1)

	tc.pendingMu.Lock()
	tc.pending[req.ID] = respChan
	log.Printf("[debug] Registered pending request: ID=%s, Method=%s, Path=%s", req.ID, req.Method, req.Path)
	tc.pendingMu.Unlock()

	defer func() {
		tc.pendingMu.Lock()
		delete(tc.pending, req.ID)
		log.Printf("[debug] Removed pending request: ID=%s", req.ID)
		tc.pendingMu.Unlock()
	}()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	log.Printf("[debug] Sending request to tunnel-client: %d bytes", len(data))

	tc.writeMu.Lock()
	err = tc.conn.WriteMessage(websocket.TextMessage, data)
	tc.writeMu.Unlock()

	if err != nil {
		log.Printf("[debug] Failed to send request: %v", err)
		return nil, err
	}

	log.Printf("[debug] Request sent, waiting for response (timeout=120s)")

	select {
	case resp := <-respChan:
		log.Printf("[debug] Received response from channel: StatusCode=%d", resp.StatusCode)
		return resp, nil
	case <-time.After(120 * time.Second):
		log.Printf("[debug] Request timeout for ID=%s", req.ID)
		return nil, ErrTunnelTimeout
	case <-tc.closeChan:
		log.Printf("[debug] Connection closed while waiting for ID=%s", req.ID)
		return nil, ErrTunnelNotFound
	}
}

func (tc *TunnelConnection) readLoop(m *Manager) {
	defer func() {
		tc.Close()
		m.removeConnection(tc)
	}()

	for {
		_, message, err := tc.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[tunnel] Read error for %s: %v", tc.subdomain, err)
			}
			return
		}

		if len(message) == 0 {
			continue
		}

		var tunnelEvent TunnelEvent
		if err := json.Unmarshal(message, &tunnelEvent); err == nil && tunnelEvent.Event == "sse" {
			m.broadcastEvent(tc.subdomain, tunnelEvent.Data)
			continue
		}

		var resp TunnelResponse
		if err := json.Unmarshal(message, &resp); err != nil {
			log.Printf("[tunnel] Failed to unmarshal response: %v (raw: %s)", err, string(message))
			continue
		}

		log.Printf("[debug] Parsed response: ID=%s, StatusCode=%d, BodyLen=%d", resp.ID, resp.StatusCode, len(resp.Body))

		tc.pendingMu.RLock()
		pendingKeys := make([]string, 0, len(tc.pending))
		for k := range tc.pending {
			pendingKeys = append(pendingKeys, k)
		}
		log.Printf("[debug] Pending request IDs: %v", pendingKeys)

		if ch, ok := tc.pending[resp.ID]; ok {
			log.Printf("[debug] Found pending channel for ID=%s, sending response", resp.ID)
			select {
			case ch <- &resp:
				log.Printf("[debug] Response sent to channel for ID=%s", resp.ID)
			default:
				log.Printf("[debug] Channel full/closed for ID=%s, response dropped", resp.ID)
			}
		} else {
			log.Printf("[debug] No pending request found for ID=%s", resp.ID)
		}
		tc.pendingMu.RUnlock()
	}
}

func (tc *TunnelConnection) pingLoop(m *Manager) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tc.writeMu.Lock()
			err := tc.conn.WriteMessage(websocket.PingMessage, nil)
			tc.writeMu.Unlock()
			if err != nil {
				return
			}
			if m.onHeartbeat != nil {
				m.onHeartbeat(tc.subdomain)
			}
		case <-tc.closeChan:
			return
		}
	}
}

func (tc *TunnelConnection) Close() {
	tc.closeOnce.Do(func() {
		close(tc.closeChan)
		tc.conn.Close()
	})
}

func ReadRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func GenerateRequestID() string {
	return time.Now().Format("20060102150405.000000000")
}

func (m *Manager) HandleEventWebSocket(w http.ResponseWriter, r *http.Request, subdomain string) error {
	conn, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}

	client := &EventClient{
		conn:      conn,
		subdomain: subdomain,
		closeChan: make(chan struct{}),
	}

	m.mu.Lock()
	if m.eventClients[subdomain] == nil {
		m.eventClients[subdomain] = make(map[*EventClient]struct{})
	}
	m.eventClients[subdomain][client] = struct{}{}
	clientCount := len(m.eventClients[subdomain])
	m.mu.Unlock()

	log.Printf("[events] Client connected for %s (total: %d)", subdomain, clientCount)

	go client.readLoop(m)
	go client.pingLoop()

	return nil
}

func (m *Manager) broadcastEvent(subdomain string, data json.RawMessage) {
	m.mu.RLock()
	clients := m.eventClients[subdomain]
	if clients == nil || len(clients) == 0 {
		m.mu.RUnlock()
		return
	}

	clientList := make([]*EventClient, 0, len(clients))
	for client := range clients {
		clientList = append(clientList, client)
	}
	m.mu.RUnlock()

	for _, client := range clientList {
		client.writeMu.Lock()
		err := client.conn.WriteMessage(websocket.TextMessage, data)
		client.writeMu.Unlock()
		if err != nil {
			log.Printf("[events] Failed to send to client: %v", err)
			client.Close()
			m.removeEventClient(client)
		}
	}
}

func (m *Manager) removeEventClient(client *EventClient) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if clients, ok := m.eventClients[client.subdomain]; ok {
		delete(clients, client)
		if len(clients) == 0 {
			delete(m.eventClients, client.subdomain)
		}
		log.Printf("[events] Client removed for %s (remaining: %d)", client.subdomain, len(clients))
	}
}

func (ec *EventClient) readLoop(m *Manager) {
	defer func() {
		ec.Close()
		m.removeEventClient(ec)
	}()

	for {
		_, _, err := ec.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[events] Read error for %s: %v", ec.subdomain, err)
			}
			return
		}
	}
}

func (ec *EventClient) pingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ec.writeMu.Lock()
			err := ec.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
			ec.writeMu.Unlock()
			if err != nil {
				return
			}
		case <-ec.closeChan:
			return
		}
	}
}

func (ec *EventClient) Close() {
	ec.closeOnce.Do(func() {
		close(ec.closeChan)
		ec.conn.Close()
	})
}
