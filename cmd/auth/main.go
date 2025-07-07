// @title Auth Service API
// @version 1.0
// @description JWT authentication service API
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

package main

import (
	"jwt-auth/internal/auth"
	"jwt-auth/internal/config"
	"jwt-auth/internal/http-server/handlers"
	"jwt-auth/internal/lib/logger/sl"
	authMiddleware "jwt-auth/internal/middleware"
	"jwt-auth/internal/storage/postgres"
	"log/slog"
	"net/http"
	"os"

	_ "jwt-auth/docs"

	_ "github.com/lib/pq"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
)

const (
	envLocal = "local"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info("starting auth", slog.Any("cfg", cfg))
	storage, err := postgres.New(
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.User,
		cfg.Postgres.Password,
		cfg.Postgres.DBName,
	)

	if err != nil {
		log.Error("failed to init storage", sl.Err(err))
		os.Exit(1)
	}

	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	authService := auth.NewService(log, storage, cfg.Secret, cfg.TokenTTL, os.Getenv("WEBHOOK_URL"))

	router.Post("/gettokens", handlers.GetTokens(log, authService))
	router.Post("/refresh", handlers.Refresh(log, authService))
	router.Post("/logout", handlers.Logout(log, authService))

	router.Group(func(r chi.Router) {
		r.Use(authMiddleware.AuthMiddleware(log, authService))
		r.Get("/user", handlers.GetGUIDCurrentUser(log, authService))
		r.Post("/logout", handlers.Logout(log, authService))
	})

	router.Get("/swagger/*", httpSwagger.Handler())

	log.Info("starting server", slog.String("address", cfg.HTTPServer.Address))

	srv := &http.Server{
		Addr:         cfg.HTTPServer.Address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Error("failed to start server")
	}

	log.Error("server stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
