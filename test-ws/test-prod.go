package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

type HeartbeatMessage struct {
	Type string `json:"type"`
	Ts   int64  `json:"ts"`
}

func main() {
	relayURL := flag.String("url", "wss://opencode-relay.azurewebsites.net", "Relay URL")
	subdomain := flag.String("subdomain", "", "Subdomain")
	authUser := flag.String("auth_user", "", "Auth user")
	authPassword := flag.String("auth_password", "", "Auth password")
	flag.Parse()

	if *subdomain == "" || *authUser == "" || *authPassword == "" {
		log.Fatal("subdomain, auth_user, and auth_password are required")
	}

	u, _ := url.Parse(*relayURL)
	u.Scheme = "wss"
	u.Path = "/api/tunnel/" + *subdomain
	q := u.Query()
	q.Set("auth_user", *authUser)
	q.Set("auth_password", *authPassword)
	u.RawQuery = q.Encode()

	log.Printf("Connecting to %s", u.String())

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	log.Println("Connected!")
	startTime := time.Now()

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, message, err := conn.ReadMessage()
		if err != nil {
			elapsed := time.Since(startTime)
			log.Printf("[%v] Read error: %v", elapsed.Round(time.Second), err)
			return
		}

		var heartbeat HeartbeatMessage
		if err := json.Unmarshal(message, &heartbeat); err == nil && heartbeat.Type == "heartbeat" {
			elapsed := time.Since(startTime)
			log.Printf("[%v] Received heartbeat, sending ack", elapsed.Round(time.Second))
			
			ack := HeartbeatMessage{Type: "heartbeat_ack", Ts: heartbeat.Ts}
			ackData, _ := json.Marshal(ack)
			if err := conn.WriteMessage(websocket.TextMessage, ackData); err != nil {
				log.Printf("Write error: %v", err)
				return
			}
			continue
		}

		elapsed := time.Since(startTime)
		log.Printf("[%v] Received: %s", elapsed.Round(time.Second), string(message))
	}
}
