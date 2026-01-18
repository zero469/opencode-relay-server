package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/zero469/opencode-relay-server/internal/models"
	"github.com/zero469/opencode-relay-server/internal/services"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		writeError(w, "password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	user, err := h.authService.Register(req.Email, req.Password)
	if err == services.ErrEmailExists {
		writeError(w, "email already exists", http.StatusConflict)
		return
	}
	if err != nil {
		writeError(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	writeJSON(w, user, http.StatusCreated)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	token, user, err := h.authService.Login(req.Email, req.Password)
	if err == services.ErrInvalidCredentials {
		writeError(w, "invalid email or password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		writeError(w, "login failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, models.LoginResponse{Token: token, User: *user}, http.StatusOK)
}

func writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, message string, status int) {
	writeJSON(w, models.ErrorResponse{Error: message}, status)
}
