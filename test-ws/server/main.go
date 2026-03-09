package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type Message struct {
	Type string `json:"type"`
	Ts   int64  `json:"ts"`
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	clientID := time.Now().UnixNano()
	log.Printf("[%d] Client connected", clientID)

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				msg := Message{Type: "heartbeat", Ts: time.Now().UnixMilli()}
				data, _ := json.Marshal(msg)
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					log.Printf("[%d] Heartbeat send failed: %v", clientID, err)
					return
				}
				log.Printf("[%d] Sent heartbeat", clientID)
			case <-done:
				return
			}
		}
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[%d] Read error: %v", clientID, err)
			close(done)
			return
		}
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		log.Printf("[%d] Received: %s", clientID, string(message))
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/ws", handleWS)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	log.Printf("WebSocket test server starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
