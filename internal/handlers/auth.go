package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/zero469/opencode-relay-server/internal/models"
	"github.com/zero469/opencode-relay-server/internal/services"
)

type AuthHandler struct {
	authService  *services.AuthService
	emailService *services.EmailService
}

func NewAuthHandler(authService *services.AuthService, emailService *services.EmailService) *AuthHandler {
	return &AuthHandler{authService: authService, emailService: emailService}
}

func (h *AuthHandler) SendVerification(w http.ResponseWriter, r *http.Request) {
	var req models.SendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		writeError(w, "email is required", http.StatusBadRequest)
		return
	}

	code, err := h.authService.CreateVerificationCode(req.Email)
	if err != nil {
		writeError(w, "failed to create verification code", http.StatusInternalServerError)
		return
	}

	if err := h.emailService.SendVerificationCode(req.Email, code); err != nil {
		writeError(w, "failed to send verification email", http.StatusInternalServerError)
		return
	}

	writeJSON(w, models.MessageResponse{Message: "verification code sent"}, http.StatusOK)
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

	if req.Code == "" {
		writeError(w, "verification code is required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		writeError(w, "password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	user, err := h.authService.Register(req.Email, req.Password, req.Code)
	if err == services.ErrInvalidCode {
		writeError(w, "invalid or expired verification code", http.StatusBadRequest)
		return
	}
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
