package database

import (
	"database/sql"
	"time"

	"github.com/zero469/opencode-relay-server/internal/models"
)

func (db *DB) CreateUser(email, passwordHash string) (*models.User, error) {
	result, err := db.Exec(
		"INSERT INTO users (email, password_hash) VALUES (?, ?)",
		email, passwordHash,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return db.GetUserByID(id)
}

func (db *DB) GetUserByID(id int64) (*models.User, error) {
	user := &models.User{}
	err := db.QueryRow(
		"SELECT id, email, password_hash, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *DB) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := db.QueryRow(
		"SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = ?",
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *DB) CreateDevice(userID int64, name, subdomain string) (*models.Device, error) {
	result, err := db.Exec(
		"INSERT INTO devices (user_id, name, subdomain) VALUES (?, ?, ?)",
		userID, name, subdomain,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return db.GetDeviceByID(id)
}

func (db *DB) GetDeviceByID(id int64) (*models.Device, error) {
	device := &models.Device{}
	var lastSeen sql.NullTime
	err := db.QueryRow(
		"SELECT id, user_id, name, subdomain, online, last_seen, created_at, updated_at FROM devices WHERE id = ?",
		id,
	).Scan(&device.ID, &device.UserID, &device.Name, &device.Subdomain, &device.Online, &lastSeen, &device.CreatedAt, &device.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		device.LastSeen = lastSeen.Time
	}
	return device, nil
}

func (db *DB) GetDeviceBySubdomain(subdomain string) (*models.Device, error) {
	device := &models.Device{}
	var lastSeen sql.NullTime
	err := db.QueryRow(
		"SELECT id, user_id, name, subdomain, online, last_seen, created_at, updated_at FROM devices WHERE subdomain = ?",
		subdomain,
	).Scan(&device.ID, &device.UserID, &device.Name, &device.Subdomain, &device.Online, &lastSeen, &device.CreatedAt, &device.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		device.LastSeen = lastSeen.Time
	}
	return device, nil
}

func (db *DB) GetDevicesByUserID(userID int64) ([]*models.Device, error) {
	rows, err := db.Query(
		"SELECT id, user_id, name, subdomain, online, last_seen, created_at, updated_at FROM devices WHERE user_id = ? ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*models.Device
	for rows.Next() {
		device := &models.Device{}
		var lastSeen sql.NullTime
		if err := rows.Scan(&device.ID, &device.UserID, &device.Name, &device.Subdomain, &device.Online, &lastSeen, &device.CreatedAt, &device.UpdatedAt); err != nil {
			return nil, err
		}
		if lastSeen.Valid {
			device.LastSeen = lastSeen.Time
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func (db *DB) UpdateDevice(id int64, name string) (*models.Device, error) {
	_, err := db.Exec(
		"UPDATE devices SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		name, id,
	)
	if err != nil {
		return nil, err
	}
	return db.GetDeviceByID(id)
}

func (db *DB) DeleteDevice(id int64) error {
	_, err := db.Exec("DELETE FROM devices WHERE id = ?", id)
	return err
}

func (db *DB) UpdateDeviceHeartbeat(id int64) error {
	_, err := db.Exec(
		"UPDATE devices SET online = TRUE, last_seen = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		time.Now(), id,
	)
	return err
}

func (db *DB) MarkOfflineDevices(timeout time.Duration) error {
	cutoff := time.Now().Add(-timeout)
	_, err := db.Exec(
		"UPDATE devices SET online = FALSE WHERE online = TRUE AND last_seen < ?",
		cutoff,
	)
	return err
}
