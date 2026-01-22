package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zero469/opencode-relay-server/internal/middleware"
	"github.com/zero469/opencode-relay-server/internal/models"
	"github.com/zero469/opencode-relay-server/internal/services"
)

type PairingHandler struct {
	pairingService *services.PairingService
}

func NewPairingHandler(pairingService *services.PairingService) *PairingHandler {
	return &PairingHandler{pairingService: pairingService}
}

func (h *PairingHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	pr, err := h.pairingService.CreatePairingRequest(userID)
	if err != nil {
		writeError(w, "failed to create pairing request", http.StatusInternalServerError)
		return
	}

	writeJSON(w, models.CreatePairingResponse{
		ID:          pr.ID,
		PairingCode: pr.PairingCode,
		ExpiresAt:   pr.ExpiresAt,
	}, http.StatusCreated)
}

func (h *PairingHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	id := extractPairingID(r.URL.Path)

	resp, err := h.pairingService.GetPairingStatus(id, userID)
	if err == services.ErrPairingNotFound {
		writeError(w, "pairing request not found", http.StatusNotFound)
		return
	}
	if err == services.ErrUserMismatch {
		writeError(w, "unauthorized", http.StatusForbidden)
		return
	}
	if err != nil {
		writeError(w, "failed to get pairing status", http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

func (h *PairingHandler) Complete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	id := extractPairingID(r.URL.Path)

	var req models.CompletePairingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.DeviceName == "" {
		writeError(w, "device_name is required", http.StatusBadRequest)
		return
	}

	device, err := h.pairingService.CompletePairing(id, req.PairingCode, userID, req.DeviceName)
	if err == services.ErrPairingNotFound {
		writeError(w, "pairing request not found", http.StatusNotFound)
		return
	}
	if err == services.ErrUserMismatch {
		writeError(w, "unauthorized", http.StatusForbidden)
		return
	}
	if err == services.ErrInvalidPairing {
		writeError(w, "invalid pairing code", http.StatusBadRequest)
		return
	}
	if err == services.ErrPairingExpired {
		writeError(w, "pairing request expired", http.StatusGone)
		return
	}
	if err == services.ErrPairingUsed {
		writeError(w, "pairing request already used", http.StatusConflict)
		return
	}
	if err != nil {
		writeError(w, "failed to complete pairing", http.StatusInternalServerError)
		return
	}

	writeJSON(w, device, http.StatusOK)
}

func extractPairingID(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "pairing" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
