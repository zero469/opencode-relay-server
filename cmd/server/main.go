package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zero469/opencode-relay-server/internal/config"
	"github.com/zero469/opencode-relay-server/internal/database"
	"github.com/zero469/opencode-relay-server/internal/handlers"
	"github.com/zero469/opencode-relay-server/internal/middleware"
	"github.com/zero469/opencode-relay-server/internal/services"
	"github.com/zero469/opencode-relay-server/internal/tunnel"
)

func main() {
	cfg := config.Load()

	localPath := cfg.DatabasePath
	remotePath := ""

	// If DATABASE_PATH points to Azure Files mount, use local disk for SQLite
	if strings.HasPrefix(cfg.DatabasePath, "/data/") {
		if _, err := os.Stat(filepath.Dir(cfg.DatabasePath)); err == nil {
			remotePath = cfg.DatabasePath
			localPath = "/tmp/" + filepath.Base(cfg.DatabasePath)

			if _, err := os.Stat(remotePath); err == nil {
				log.Printf("Copying database from %s to %s", remotePath, localPath)
				if err := copyFile(remotePath, localPath); err != nil {
					log.Printf("Warning: failed to copy database from remote: %v", err)
				} else {
					log.Printf("Database copied successfully")
				}
			} else {
				log.Printf("No remote database found at %s, starting fresh", remotePath)
			}
		}
	}

	log.Printf("Database path: %s (remote: %s)", localPath, remotePath)

	db, err := database.New(localPath)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Mark all devices offline on server startup
	// They will be marked online again when tunnel-clients reconnect
	if count, err := db.MarkAllDevicesOffline(); err != nil {
		log.Printf("Warning: failed to mark devices offline on startup: %v", err)
	} else if count > 0 {
		log.Printf("Marked %d device(s) offline on server startup", count)
	}

	authService := services.NewAuthService(db, cfg.JWTSecret, cfg.SingleUserMode)

	if err := authService.EnsureAdminUser(cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Printf("Warning: failed to create admin user: %v", err)
	} else if cfg.AdminEmail != "" {
		log.Printf("Admin user ensured: %s", cfg.AdminEmail)
	}

	deviceService := services.NewDeviceService(db, cfg)
	emailService := services.NewEmailService(cfg)
	pairingService := services.NewPairingService(db, cfg)

	tunnelManager := tunnel.NewManager()
	tunnelHandler := tunnel.NewHandler(tunnelManager, db)

	authHandler := handlers.NewAuthHandler(authService, emailService)
	deviceHandler := handlers.NewDeviceHandler(deviceService)
	pairingHandler := handlers.NewPairingHandler(pairingService)

	authMiddleware := middleware.Auth(authService)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/send-verification", authHandler.SendVerification)
	mux.HandleFunc("POST /api/register", authHandler.Register)
	mux.HandleFunc("POST /api/login", authHandler.Login)
	mux.HandleFunc("POST /api/auto-login", authHandler.AutoLogin)

	mux.HandleFunc("GET /api/heartbeat", deviceHandler.Heartbeat)

	mux.Handle("POST /api/devices", authMiddleware(http.HandlerFunc(deviceHandler.Register)))
	mux.Handle("GET /api/devices", authMiddleware(http.HandlerFunc(deviceHandler.List)))
	mux.Handle("GET /api/devices/{id}", authMiddleware(http.HandlerFunc(deviceHandler.Get)))
	mux.Handle("PUT /api/devices/{id}", authMiddleware(http.HandlerFunc(deviceHandler.Update)))
	mux.Handle("DELETE /api/devices/{id}", authMiddleware(http.HandlerFunc(deviceHandler.Delete)))
	mux.Handle("GET /api/devices/{id}/frpc-config", authMiddleware(http.HandlerFunc(deviceHandler.GetFrpcConfig)))

	mux.Handle("POST /api/pairing", authMiddleware(http.HandlerFunc(pairingHandler.Create)))
	mux.Handle("GET /api/pairing/{id}/status", authMiddleware(http.HandlerFunc(pairingHandler.GetStatus)))
	mux.Handle("POST /api/pairing/{id}/complete", authMiddleware(http.HandlerFunc(pairingHandler.Complete)))

	mux.HandleFunc("GET /api/tunnel/{subdomain}", tunnelHandler.HandleTunnelConnect)
	mux.HandleFunc("GET /api/events/{subdomain}", tunnelHandler.HandleEventConnect)
	mux.HandleFunc("POST /api/device/verify", tunnelHandler.HandleDeviceVerify)
	mux.HandleFunc("/proxy/", tunnelHandler.HandleProxy)

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Apple App Site Association for iOS password autosave (SharedWebCredentials)
	mux.HandleFunc("GET /.well-known/apple-app-site-association", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
  "applinks": {
    "details": [
      {
        "appID": "9N465R4RJ8.com.opencode.anywhere",
        "paths": ["*"]
      }
    ]
  },
  "webcredentials": {
    "apps": ["9N465R4RJ8.com.opencode.anywhere"]
  }
}`))
	})

	mux.HandleFunc("GET /install.sh", handlers.ServeInstallScript)
	mux.HandleFunc("GET /install.ps1", handlers.ServeInstallScriptPS1)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			db.MarkOfflineDevices(60 * time.Second)
			db.DeleteExpiredPairingRequests()
		}
	}()

	stopSync := make(chan struct{})
	if remotePath != "" {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					syncDatabase(localPath, remotePath)
				case <-stopSync:
					return
				}
			}
		}()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		close(stopSync)
		if remotePath != "" {
			syncDatabase(localPath, remotePath)
		}
		db.Close()
		os.Exit(0)
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

func syncDatabase(localPath, remotePath string) {
	start := time.Now()
	if err := copyFile(localPath, remotePath); err != nil {
		log.Printf("[sync] Failed to sync database to %s: %v", remotePath, err)
	} else {
		log.Printf("[sync] Database synced to %s (%v)", remotePath, time.Since(start))
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
