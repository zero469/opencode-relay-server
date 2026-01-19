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
	ID           int64     `json:"id"`
	UserID       int64     `json:"user_id"`
	Name         string    `json:"name"`
	Subdomain    string    `json:"subdomain"`
	AuthUser     string    `json:"auth_user"`
	AuthPassword string    `json:"auth_password"`
	Online       bool      `json:"online"`
	LastSeen     time.Time `json:"last_seen"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type SendVerificationRequest struct {
	Email string `json:"email"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"code"`
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
	ServerAddr   string `json:"server_addr"`
	ServerPort   string `json:"server_port"`
	Token        string `json:"token"`
	Subdomain    string `json:"subdomain"`
	Domain       string `json:"domain"`
	LocalPort    string `json:"local_port"`
	AuthUser     string `json:"auth_user"`
	AuthPassword string `json:"auth_password"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type MessageResponse struct {
	Message string `json:"message"`
}
