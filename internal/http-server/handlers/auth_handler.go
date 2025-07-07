package handlers

import (
	"encoding/json"
	"jwt-auth/internal/lib/logger/sl"
	"jwt-auth/internal/models"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

// @Description Ответ обработчика
type Response struct {
	Status string      `json:"status" example:"OK"`
	Error  string      `json:"error,omitempty" example:"something went wrong"`
	Data   interface{} `json:"data,omitempty"`
}

type GetTokensResponseSwagger struct {
	Status string                   `json:"status" example:"OK"`
	Data   models.GetTokensResponse `json:"data"`
	Error  string                   `json:"error,omitempty"`
}

type RefreshResponseSwagger struct {
	Status string                   `json:"status" example:"OK"`
	Data   models.GetTokensResponse `json:"data"`
	Error  string                   `json:"error,omitempty"`
}

type UserResponseSwagger struct {
	Status string              `json:"status" example:"OK"`
	Data   models.UserResponse `json:"data"`
	Error  string              `json:"error,omitempty"`
}

type ErrorResponseSwagger struct {
	Status string `json:"status" example:"Error"`
	Error  string `json:"error" example:"something went wrong"`
	Data   any    `json:"data,omitempty"`
}

type BadRequestErrorSwagger struct {
	Status string `json:"status" example:"Error"`
	Error  string `json:"error" example:"GUID parameter is required"`
}

type UnauthorizedErrorSwagger struct {
	Status string `json:"status" example:"Error"`
	Error  string `json:"error" example:"Invalid tokens or unauthorized"`
}

type InternalErrorSwagger struct {
	Status string `json:"status" example:"Error"`
	Error  string `json:"error" example:"Internal server error"`
}

type authService interface {
	GetTokens(guid string, userAgent string, ip string) (*models.GetTokensResponse, error)
	Refresh(accessToken, refreshToken, userAgent, ip string) (*models.GetTokensResponse, error)
	GetCurrentUserAndSession(accessToken string) (string, string, error)
	GetRefreshTokenBySession(sessionID string) (*models.Refresh, error)
	IsSessionExists(sessionID string) (bool, error)
	Logout(guid, sessionID string) error
}

// GetTokens godoc
// @Summary      Получить пару токенов
// @Description  Генерирует новую пару access и refresh токенов для пользователя по GUID
// @Tags         auth
// @Param        guid   query   string  true  "GUID пользователя"  example(123e4567-e89b-12d3-a456-426614174000)
// @Success      200    {object}  GetTokensResponseSwagger  "OK"
// @Failure      400    {object}  BadRequestErrorSwagger  "GUID parameter is required"
// @Failure      500    {object}  ErrorResponseSwagger  "failed to generate tokens"
// @Router       /gettokens [post]
// @Example      200 {object} GetTokensResponseSwagger '{"status":"OK","data":{"access_token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...","refresh_token":"base64string..."}}'
// @Example      400 {object} BadRequestErrorSwagger '{"status":"Error","error":"GUID parameter is required"}'
// @Example      500 {object} ErrorResponseSwagger '{"status":"Error","error":"failed to generate tokens"}'
func GetTokens(log *slog.Logger, authService authService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.GetTokens"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		guid := r.URL.Query().Get("guid")

		if guid == "" {
			log.Error("empty GUID provided")
			w.WriteHeader(http.StatusBadRequest)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "GUID parameter is required",
			})
			return
		}

		userAgent := r.UserAgent()
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		}

		tokens, err := authService.GetTokens(guid, userAgent, ip)
		if err != nil {
			log.Error("failed to get tokens", sl.Err(err))
			w.WriteHeader(http.StatusInternalServerError)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "failed to generate tokens",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		respObj := GetTokensResponseSwagger{
			Status: "OK",
			Data:   *tokens,
		}
		render.JSON(w, r, respObj)
	}
}

// Refresh godoc
// @Summary      Обновить пару токенов
// @Description  Обновляет access и refresh токены по действующей паре
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body   models.RefreshRequest  true  "Пара токенов"
// @Success      200   {object} RefreshResponseSwagger "OK"
// @Failure      400   {object} ErrorResponseSwagger "Both access_token and refresh_token are required"
// @Failure      401   {object} UnauthorizedErrorSwagger "Invalid tokens or unauthorized"
// @Router       /refresh [post]
// @Example      request {"access_token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...","refresh_token":"base64string..."}
// @Example      200 {object} RefreshResponseSwagger '{"status":"OK","data":{"access_token":"...","refresh_token":"..."}}'
// @Example      400 {object} ErrorResponseSwagger '{"status":"Error","error":"Both access_token and refresh_token are required"}'
// @Example      401 {object} UnauthorizedErrorSwagger '{"status":"Error","error":"Invalid tokens or unauthorized"}'
func Refresh(log *slog.Logger, authService authService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.Refresh"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req models.RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Error("failed to decode request", sl.Err(err))
			w.WriteHeader(http.StatusBadRequest)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "Invalid request format",
			})
			return
		}

		if req.AccessToken == "" || req.RefreshToken == "" {
			log.Error("empty tokens provided")
			w.WriteHeader(http.StatusBadRequest)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "Both access_token and refresh_token are required",
			})
			return
		}

		userAgent := r.UserAgent()
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		}

		log.Info("refreshing tokens",
			slog.String("user_agent", userAgent),
			slog.String("ip", ip),
		)

		tokens, err := authService.Refresh(req.AccessToken, req.RefreshToken, userAgent, ip)
		if err != nil {
			log.Error("failed to refresh tokens", sl.Err(err))
			w.WriteHeader(http.StatusUnauthorized)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "Invalid tokens or unauthorized",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		render.JSON(w, r, RefreshResponseSwagger{
			Status: "OK",
			Data:   *tokens,
		})
	}
}

// GetGUIDCurrentUser godoc
// @Summary      Получить GUID текущего пользователя
// @Description  Возвращает GUID пользователя по access токену (защищённый роут)
// @Tags         user
// @Security     BearerAuth
// @Success      200 {object} UserResponseSwagger "OK"
// @Failure      401 {object} UnauthorizedErrorSwagger "Invalid or expired token"
// @Failure      500 {object} InternalErrorSwagger "Internal server error"
// @Router       /user [get]
// @Example      200 {object} UserResponseSwagger '{"status":"OK","data":{"guid":"123e4567-e89b-12d3-a456-426614174000"}}'
// @Example      401 {object} UnauthorizedErrorSwagger '{"status":"Error","error":"Invalid or expired token"}'
// @Example      500 {object} InternalErrorSwagger '{"status":"Error","error":"Internal server error"}'
func GetGUIDCurrentUser(log *slog.Logger, authService authService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.GetGUIDCurrentUser"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		guid, ok := r.Context().Value("user_guid").(string)
		if !ok {
			log.Error("user guid not found in context")
			w.WriteHeader(http.StatusInternalServerError)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "Internal server error",
			})
			return
		}

		log.Info("user info retrieved", slog.String("guid", guid))

		userResponse := models.UserResponse{
			GUID: guid,
		}

		w.WriteHeader(http.StatusOK)
		render.JSON(w, r, UserResponseSwagger{
			Status: "OK",
			Data:   userResponse,
		})
	}
}

// Logout godoc
// @Summary      Деавторизация пользователя
// @Description  Деавторизует пользователя и инвалидирует все токены сессии
// @Tags         auth
// @Security     BearerAuth
// @Success      204   {string} string "No Content"
// @Failure      401   {object} UnauthorizedErrorSwagger "Invalid or expired token"
// @Failure      500   {object} InternalErrorSwagger "Internal server error"
// @Router       /logout [post]
// @Example      204 {string} string ""
// @Example      401 {object} UnauthorizedErrorSwagger '{"status":"Error","error":"Invalid or expired token"}'
// @Example      500 {object} InternalErrorSwagger '{"status":"Error","error":"Internal server error"}'
func Logout(log *slog.Logger, authService authService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.Logout"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		guid, ok := r.Context().Value("user_guid").(string)
		if !ok {
			log.Error("user guid not found in context")
			w.WriteHeader(http.StatusInternalServerError)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "Internal server error",
			})
			return
		}

		sessionID, ok := r.Context().Value("session_id").(string)
		if !ok {
			log.Error("user session id not found in context")
			w.WriteHeader(http.StatusInternalServerError)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "Internal server error",
			})
			return
		}

		err := authService.Logout(guid, sessionID)
		if err != nil {
			log.Error("failed to logout", sl.Err(err))
			w.WriteHeader(http.StatusInternalServerError)
			render.JSON(w, r, ErrorResponseSwagger{
				Status: "Error",
				Error:  "failed to logout",
			})
			return
		}

		log.Info("user logged out successfully")

		w.WriteHeader(http.StatusOK)
	}
}
