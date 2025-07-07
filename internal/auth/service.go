package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"jwt-auth/internal/lib/logger/sl"
	"jwt-auth/internal/models"
	"jwt-auth/internal/storage/postgres"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	storage        *postgres.Storage
	accessTokenTTL time.Duration
	secret         []byte
	webhookURL     string
	log            *slog.Logger
}

type JWTClaims struct {
	GUID      string `json:"guid"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

func NewService(log *slog.Logger, storage *postgres.Storage, jwtSecret string, accessTokenTTL string, webhookURL string) *Service {
	ttl, err := time.ParseDuration(accessTokenTTL)
	if err != nil {
		ttl = 15 * time.Minute
	}

	return &Service{
		storage:        storage,
		accessTokenTTL: ttl,
		secret:         []byte(jwtSecret),
		webhookURL:     webhookURL,
		log:            log,
	}
}

func (s *Service) GetTokens(guid string, userAgent string, ip string) (*models.GetTokensResponse, error) {
	const op = "auth.service.GetTokens"

	sessionID := s.generateSessionID()

	accessToken, err := s.generateAccessToken(guid, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%s: generate access token: %w", op, err)
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("%s: generate refresh token: %w", op, err)
	}

	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("%s: hash refresh token: %w", op, err)
	}

	err = s.storage.SaveRefreshToken(guid, sessionID, string(hashedRefresh), userAgent, ip)
	if err != nil {
		return nil, fmt.Errorf("%s: save refresh token: %w", op, err)
	}

	return &models.GetTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) Refresh(accessToken, refreshToken, userAgent, ip string) (*models.GetTokensResponse, error) {
	const op = "auth.service.Refresh"

	guid, sessionID, err := s.GetCurrentUserAndSession(accessToken)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid access token: %w", op, err)
	}

	storedToken, err := s.storage.GetRefreshTokenBySessionID(sessionID)
	if err != nil {
		return nil, fmt.Errorf("%s: get refresh token: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedToken.Hash), []byte(refreshToken)); err != nil {
		return nil, fmt.Errorf("%s: token pair mismatch", op)
	}

	if storedToken.GUID != guid {
		return nil, fmt.Errorf("%s: token pair mismatch", op)
	}

	if storedToken.UserAgent != userAgent {
		s.storage.DeleteAllRefreshTokens(storedToken.GUID)
		return nil, fmt.Errorf("%s: user agent mismatch", op)
	}

	if storedToken.IP != ip {
		s.sendIPChangeWebhook(storedToken.GUID, storedToken.IP, ip)
	}

	s.storage.DeleteRefreshTokensBySession(sessionID)

	return s.GetTokens(storedToken.GUID, userAgent, ip)
}

func (s *Service) GetRefreshTokenBySession(sessionID string) (*models.Refresh, error) {
	const op = "auth.service.GetRefreshTokenBySession"

	refresh, err := s.storage.GetRefreshTokenBySessionID(sessionID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return refresh, nil
}

func (s *Service) generateSessionID() string {
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	return base64.StdEncoding.EncodeToString(randomBytes)
}

func (s *Service) generateAccessToken(guid, sessionID string) (string, error) {
	claims := JWTClaims{
		GUID:      guid,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(s.secret)
}

func (s *Service) generateRefreshToken() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(randomBytes), nil
}

func (s *Service) sendIPChangeWebhook(guid, oldIP, newIP string) {
	webhookURL := s.webhookURL
	if webhookURL == "" {
		s.log.Warn("WEBHOOK_URL is not set")
		return
	}

	payload := map[string]string{
		"guid":   guid,
		"old_ip": oldIP,
		"new_ip": newIP,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.log.Error("failed to marshal webhook payload", sl.Err(err))
		return
	}

	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewBuffer(body))
	if err != nil {
		s.log.Error("failed to create webhook request", sl.Err(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.log.Error("failed to send webhook", sl.Err(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.log.Error("webhook returned non-2xx status",
			slog.Int("status", resp.StatusCode),
		)
		return
	}

	s.log.Info("IP change webhook sent",
		slog.String("guid", guid),
		slog.Int("status", resp.StatusCode),
	)
}

func (s *Service) GetCurrentUserAndSession(accessToken string) (string, string, error) {
	const op = "auth.service.GetCurrentUserAndSession"

	tokenString := strings.TrimPrefix(accessToken, "Bearer ")

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secret, nil
	})

	if err != nil {
		return "", "", fmt.Errorf("%s: parse token: %w", op, err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims.GUID, claims.SessionID, nil
	}

	return "", "", fmt.Errorf("%s: invalid token", op)
}

func (s *Service) IsSessionExists(sessionID string) (bool, error) {
	const op = "auth.service.IsSessionExists"

	exists, err := s.storage.IsSessionExists(sessionID)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return exists, nil
}

func (s *Service) Logout(guid, sessionID string) error {
	const op = "auth.service.Logout"

	err := s.storage.DeleteRefreshTokensBySession(sessionID)
	if err != nil {
		return fmt.Errorf("%s: failed to delete refresh tokens: %w", op, err)
	}

	return nil
}
