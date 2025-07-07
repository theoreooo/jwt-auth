package middleware

import (
	"context"
	"jwt-auth/internal/auth"
	"jwt-auth/internal/lib/logger/sl"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	Status string      `json:"status" example:"OK"`
	Error  string      `json:"error,omitempty" example:"something went wrong"`
	Data   interface{} `json:"data,omitempty"`
}

func AuthMiddleware(log *slog.Logger, authService *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const op = "middleware.AuthMiddleware"

			log = log.With(
				slog.String("op", op),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			)

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				log.Error("missing authorization header")
				w.WriteHeader(http.StatusUnauthorized)
				render.JSON(w, r, Response{
					Status: "Error",
					Error:  "Authorization header is required",
				})
				return
			}

			guid, sessionID, err := authService.GetCurrentUserAndSession(authHeader)
			if err != nil {
				log.Error("invalid token", sl.Err(err))
				w.WriteHeader(http.StatusUnauthorized)
				render.JSON(w, r, Response{
					Status: "Error",
					Error:  "Invalid or expired token",
				})
				return
			}

			exists, err := authService.IsSessionExists(sessionID)
			if err != nil {
				log.Error("failed to check session", sl.Err(err))
				w.WriteHeader(http.StatusInternalServerError)
				render.JSON(w, r, Response{
					Status: "Error",
					Error:  "Internal server error",
				})
				return
			}

			if !exists {
				log.Error("session not found - user logged out",
					slog.String("guid", guid),
					slog.String("session_id", sessionID),
				)
				w.WriteHeader(http.StatusUnauthorized)
				render.JSON(w, r, Response{
					Status: "Error",
					Error:  "User is logged out",
				})
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, "user_guid", guid)
			ctx = context.WithValue(ctx, "session_id", sessionID)
			r = r.WithContext(ctx)

			log.Info("user authenticated",
				slog.String("guid", guid),
				slog.String("session_id", sessionID),
			)

			next.ServeHTTP(w, r)
		})
	}
}
