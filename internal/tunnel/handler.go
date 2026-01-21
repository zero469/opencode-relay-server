package tunnel

import (
	"log"
	"net/http"
	"strings"

	"github.com/zero469/opencode-relay-server/internal/database"
)

type Handler struct {
	manager *Manager
	db      *database.DB
}

func NewHandler(manager *Manager, db *database.DB) *Handler {
	manager.SetCallbacks(
		func(subdomain string) {
			if device, err := db.GetDeviceBySubdomain(subdomain); err == nil {
				db.UpdateDeviceHeartbeat(device.ID)
			}
		},
		func(subdomain string) {
			if device, err := db.GetDeviceBySubdomain(subdomain); err == nil {
				db.MarkDeviceOffline(device.ID)
			}
		},
	)

	return &Handler{
		manager: manager,
		db:      db,
	}
}

func (h *Handler) HandleTunnelConnect(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, "subdomain required", http.StatusBadRequest)
		return
	}
	subdomain := parts[3]

	device, err := h.db.GetDeviceBySubdomain(subdomain)
	if err != nil {
		log.Printf("[tunnel] Device not found: %s", subdomain)
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	authUser := r.URL.Query().Get("auth_user")
	authPassword := r.URL.Query().Get("auth_password")

	if authUser != device.AuthUser || authPassword != device.AuthPassword {
		log.Printf("[tunnel] Auth failed for device: %s", subdomain)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.manager.HandleWebSocket(w, r, subdomain); err != nil {
		log.Printf("[tunnel] WebSocket upgrade failed for %s: %v", subdomain, err)
		return
	}
}

func (h *Handler) HandleProxy(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.SplitN(strings.TrimPrefix(path, "/proxy/"), "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "subdomain required", http.StatusBadRequest)
		return
	}

	subdomain := parts[0]
	targetPath := "/"
	if len(parts) > 1 {
		targetPath = "/" + parts[1]
	}

	if !h.manager.IsConnected(subdomain) {
		http.Error(w, "device not connected", http.StatusServiceUnavailable)
		return
	}

	body, err := ReadRequestBody(r)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	headers := make(map[string]string)
	for key := range r.Header {
		if !isHopByHopHeader(key) {
			headers[key] = r.Header.Get(key)
		}
	}

	if r.URL.RawQuery != "" {
		targetPath = targetPath + "?" + r.URL.RawQuery
	}

	tunnelReq := &TunnelRequest{
		ID:      GenerateRequestID(),
		Method:  r.Method,
		Path:    targetPath,
		Headers: headers,
		Body:    body,
	}

	resp, err := h.manager.ForwardRequest(subdomain, tunnelReq)
	if err != nil {
		if err == ErrTunnelNotFound {
			http.Error(w, "device not connected", http.StatusServiceUnavailable)
		} else if err == ErrTunnelTimeout {
			http.Error(w, "request timeout", http.StatusGatewayTimeout)
		} else {
			http.Error(w, "tunnel error", http.StatusBadGateway)
		}
		return
	}

	for key, value := range resp.Headers {
		w.Header().Set(key, value)
	}

	w.WriteHeader(resp.StatusCode)
	if len(resp.Body) > 0 {
		w.Write(resp.Body)
	}
}

var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func isHopByHopHeader(header string) bool {
	return hopByHopHeaders[header]
}
