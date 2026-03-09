package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
)

type Message struct {
	Type string `json:"type"`
	Ts   int64  `json:"ts"`
}

func main() {
	url := flag.String("url", "ws://localhost:8080/ws", "WebSocket URL")
	flag.Parse()

	log.Printf("Connecting to %s", *url)

	conn, _, err := websocket.DefaultDialer.Dial(*url, nil)
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	log.Printf("Connected!")
	connectTime := time.Now()

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					log.Printf("Ping failed: %v", err)
					return
				}
			case <-done:
				return
			}
		}
	}()

	go func() {
		defer close(done)
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				duration := time.Since(connectTime)
				log.Printf("Connection closed after %v: %v", duration, err)
				return
			}
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))

			var msg Message
			if err := json.Unmarshal(message, &msg); err == nil && msg.Type == "heartbeat" {
				ack := Message{Type: "heartbeat_ack", Ts: msg.Ts}
				data, _ := json.Marshal(ack)
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					log.Printf("Ack send failed: %v", err)
					return
				}
				duration := time.Since(connectTime)
				log.Printf("[%v] Heartbeat ack sent", duration.Round(time.Second))
			}
		}
	}()

	select {
	case <-done:
	case <-sigChan:
		log.Println("Interrupted")
	}
}
