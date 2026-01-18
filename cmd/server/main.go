package main

import (
	"log"
	"net/http"
	"time"

	"github.com/zero469/opencode-relay-server/internal/config"
	"github.com/zero469/opencode-relay-server/internal/database"
	"github.com/zero469/opencode-relay-server/internal/handlers"
	"github.com/zero469/opencode-relay-server/internal/middleware"
	"github.com/zero469/opencode-relay-server/internal/services"
)

func main() {
	cfg := config.Load()

	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	authService := services.NewAuthService(db, cfg.JWTSecret)
	deviceService := services.NewDeviceService(db, cfg)

	authHandler := handlers.NewAuthHandler(authService)
	deviceHandler := handlers.NewDeviceHandler(deviceService)

	authMiddleware := middleware.Auth(authService)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/register", authHandler.Register)
	mux.HandleFunc("POST /api/login", authHandler.Login)

	mux.HandleFunc("GET /api/heartbeat", deviceHandler.Heartbeat)

	mux.Handle("POST /api/devices", authMiddleware(http.HandlerFunc(deviceHandler.Register)))
	mux.Handle("GET /api/devices", authMiddleware(http.HandlerFunc(deviceHandler.List)))
	mux.Handle("GET /api/devices/{id}", authMiddleware(http.HandlerFunc(deviceHandler.Get)))
	mux.Handle("PUT /api/devices/{id}", authMiddleware(http.HandlerFunc(deviceHandler.Update)))
	mux.Handle("DELETE /api/devices/{id}", authMiddleware(http.HandlerFunc(deviceHandler.Delete)))
	mux.Handle("GET /api/devices/{id}/frpc-config", authMiddleware(http.HandlerFunc(deviceHandler.GetFrpcConfig)))

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			db.MarkOfflineDevices(60 * time.Second)
		}
	}()

	handler := corsMiddleware(mux)

	log.Printf("Server starting on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
