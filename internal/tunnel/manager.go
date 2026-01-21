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

type Manager struct {
	connections  map[string]*TunnelConnection
	mu           sync.RWMutex
	upgrader     websocket.Upgrader
	onConnect    func(subdomain string)
	onDisconnect func(subdomain string)
}

func NewManager() *Manager {
	return &Manager{
		connections: make(map[string]*TunnelConnection),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
			ReadBufferSize:  1024 * 64,
			WriteBufferSize: 1024 * 64,
		},
	}
}

func (m *Manager) SetCallbacks(onConnect, onDisconnect func(subdomain string)) {
	m.onConnect = onConnect
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

	if m.onConnect != nil {
		m.onConnect(subdomain)
	}

	go tc.readLoop(m)
	go tc.pingLoop()

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
	tc.pendingMu.Unlock()

	defer func() {
		tc.pendingMu.Lock()
		delete(tc.pending, req.ID)
		tc.pendingMu.Unlock()
	}()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	tc.writeMu.Lock()
	err = tc.conn.WriteMessage(websocket.TextMessage, data)
	tc.writeMu.Unlock()

	if err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(120 * time.Second):
		return nil, ErrTunnelTimeout
	case <-tc.closeChan:
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

		var resp TunnelResponse
		if err := json.Unmarshal(message, &resp); err != nil {
			log.Printf("[tunnel] Failed to unmarshal response: %v", err)
			continue
		}

		tc.pendingMu.RLock()
		if ch, ok := tc.pending[resp.ID]; ok {
			select {
			case ch <- &resp:
			default:
			}
		}
		tc.pendingMu.RUnlock()
	}
}

func (tc *TunnelConnection) pingLoop() {
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
