package models

import "time"

type User struct {
	ID           int64     `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Device struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Name      string    `json:"name"`
	Subdomain string    `json:"subdomain"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type DeviceRegisterRequest struct {
	Name string `json:"name"`
}

type DeviceUpdateRequest struct {
	Name string `json:"name"`
}

type FrpcConfig struct {
	ServerAddr string `json:"server_addr"`
	ServerPort string `json:"server_port"`
	Token      string `json:"token"`
	Subdomain  string `json:"subdomain"`
	LocalPort  string `json:"local_port"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type MessageResponse struct {
	Message string `json:"message"`
}
