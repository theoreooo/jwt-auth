package models

import "time"

type Refresh struct {
	ID        int64     `json:"id"`
	GUID      string    `json:"guid"`
	SessionID string    `json:"session_id" db:"session_id"`
	Hash      string    `json:"refresh"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `db:"created_at"`
}

type GetTokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshRequest struct {
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type UserResponse struct {
	GUID string `json:"guid"`
}
