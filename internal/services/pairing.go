package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/zero469/opencode-relay-server/internal/config"
	"github.com/zero469/opencode-relay-server/internal/database"
	"github.com/zero469/opencode-relay-server/internal/models"
)

var (
	ErrPairingNotFound = errors.New("pairing request not found")
	ErrPairingExpired  = errors.New("pairing request expired")
	ErrPairingUsed     = errors.New("pairing request already used")
	ErrInvalidPairing  = errors.New("invalid pairing code")
	ErrUserMismatch    = errors.New("pairing request belongs to different user")
)

type PairingService struct {
	db  *database.DB
	cfg *config.Config
}

func NewPairingService(db *database.DB, cfg *config.Config) *PairingService {
	return &PairingService{db: db, cfg: cfg}
}

func (s *PairingService) CreatePairingRequest(userID int64) (*models.PairingRequest, error) {
	id := generatePairingID()
	pairingCode := generatePairingCode()
	expiresAt := time.Now().Add(2 * time.Minute)

	return s.db.CreatePairingRequest(id, userID, pairingCode, expiresAt)
}

func (s *PairingService) GetPairingStatus(id string, userID int64) (*models.PairingStatusResponse, error) {
	pr, err := s.db.GetPairingRequestByID(id)
	if err != nil {
		return nil, ErrPairingNotFound
	}

	if pr.UserID != userID {
		return nil, ErrUserMismatch
	}

	if time.Now().After(pr.ExpiresAt) && pr.Status == "pending" {
		return &models.PairingStatusResponse{Status: "expired"}, nil
	}

	resp := &models.PairingStatusResponse{Status: pr.Status}
	if pr.Status == "completed" && pr.DeviceID != nil {
		device, err := s.db.GetDeviceByID(*pr.DeviceID)
		if err == nil {
			resp.Device = device
		}
	}

	return resp, nil
}

func (s *PairingService) CompletePairing(id string, pairingCode string, userID int64, deviceName string) (*models.Device, error) {
	pr, err := s.db.GetPairingRequestByID(id)
	if err != nil {
		return nil, ErrPairingNotFound
	}

	if pr.UserID != userID {
		return nil, ErrUserMismatch
	}

	if pr.PairingCode != pairingCode {
		return nil, ErrInvalidPairing
	}

	if time.Now().After(pr.ExpiresAt) {
		return nil, ErrPairingExpired
	}

	if pr.Status != "pending" {
		return nil, ErrPairingUsed
	}

	subdomain := GenerateSubdomain()
	for {
		existing, _ := s.db.GetDeviceBySubdomain(subdomain)
		if existing == nil {
			break
		}
		subdomain = GenerateSubdomain()
	}

	authUser := GenerateRandomString(8)
	authPassword := GenerateRandomString(32)

	device, err := s.db.CreateDevice(userID, deviceName, subdomain, authUser, authPassword)
	if err != nil {
		return nil, err
	}

	if err := s.db.CompletePairingRequest(id, device.ID); err != nil {
		return nil, err
	}

	return device, nil
}

func generatePairingID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generatePairingCode() string {
	charset := "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	code := make([]byte, 9)
	rand.Read(code)
	for i := range code {
		code[i] = charset[int(code[i])%len(charset)]
	}
	return string(code[:3]) + "-" + string(code[3:6]) + "-" + string(code[6:])
}

func (s *PairingService) ParsePairingCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}
