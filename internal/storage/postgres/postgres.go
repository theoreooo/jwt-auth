package postgres

import (
	"database/sql"
	"fmt"
	"jwt-auth/internal/models"
	"time"
)

type Storage struct {
	db *sql.DB
}

func New(host, port, user, password, dbname string) (*Storage, error) {
	const op = "storage.postgres.New"

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	var db *sql.DB
	var err error

	for attempts := 5; attempts > 0; attempts-- {
		db, err = sql.Open("postgres", connStr)
		if err != nil {
			return nil, fmt.Errorf("%s: open database: %w", op, err)
		}

		err = db.Ping()
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("%s: ping database: %w", op, err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
    	id SERIAL PRIMARY KEY,
    	guid UUID NOT NULL,
    	session_id TEXT NOT NULL,
    	hash TEXT NOT NULL,
    	user_agent TEXT,
    	ip TEXT,
    	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens (session_id);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens (hash);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_session_hash ON refresh_tokens (session_id, hash);
	`

	_, err = db.Exec(schema)
	if err != nil {
		return nil, fmt.Errorf("%s: execute schema: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveRefreshToken(guid, sessionID, hash, userAgent, ip string) error {
	const op = "storage.postgres.SaveRefreshToken"

	query := `
		INSERT INTO refresh_tokens (guid, session_id, hash, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := s.db.Exec(query, guid, sessionID, hash, userAgent, ip)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) GetRefreshTokenBySessionID(sessionID string) (*models.Refresh, error) {
	const op = "storage.postgres.GetRefreshTokenBySessionID"

	query := `
		SELECT id, guid, session_id, hash, user_agent, ip, created_at
		FROM refresh_tokens
		WHERE session_id = $1
		LIMIT 1
	`

	var refresh models.Refresh
	err := s.db.QueryRow(query, sessionID).Scan(
		&refresh.ID,
		&refresh.GUID,
		&refresh.SessionID,
		&refresh.Hash,
		&refresh.UserAgent,
		&refresh.IP,
		&refresh.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: session not found", op)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &refresh, nil
}

func (s *Storage) DeleteAllRefreshTokens(guid string) error {
	const op = "storage.postgres.DeleteAllRefreshTokens"

	query := `DELETE FROM refresh_tokens WHERE guid = $1`

	_, err := s.db.Exec(query, guid)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) IsSessionExists(sessionID string) (bool, error) {
	const op = "storage.postgres.IsSessionExists"

	query := `
		SELECT EXISTS(
			SELECT 1 FROM refresh_tokens 
			WHERE session_id = $1
		)
	`

	var exists bool
	err := s.db.QueryRow(query, sessionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return exists, nil
}

func (s *Storage) DeleteRefreshTokensBySession(sessionID string) error {
	const op = "storage.postgres.DeleteRefreshTokensBySession"

	query := `DELETE FROM refresh_tokens WHERE session_id = $1`

	_, err := s.db.Exec(query, sessionID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
