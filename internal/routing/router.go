package routing

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"net/http"
	"server-alpha/internal/managers"
	"server-alpha/internal/routing/handlers"
	"time"
)

func InitRouter(databaseMgr managers.DatabaseMgr, mailMgr managers.MailMgr, jwtMgr managers.JWTMgr) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(15000 * time.Second))
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	// Initialize handlers
	postHdl := handlers.NewPostHandler(&databaseMgr)

	// Initialize user handlers
	userHdl := handlers.NewUserHandler(&databaseMgr, &jwtMgr, &mailMgr)

	// Initialize health check route
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		// Ping the database
		conn, err := databaseMgr.GetPool().Acquire(r.Context())
		if err != nil {
			http.Error(w, "Database not responding", http.StatusInternalServerError)
			return
		}
		defer conn.Release()
		w.WriteHeader(http.StatusOK)
	})

	// Initialize user routes
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Post("/", userHdl.RegisterUser)
		r.Post("/login", userHdl.LoginUser)
		r.Post("/{username}/activate", userHdl.ActivateUser)
		r.Delete("/{username}/activate", userHdl.ResendToken)

		r.With(jwtMgr.JWTMiddleware).Get("/{username}", userHdl.GetUser)
	})

	// Initialize post routes
	r.Route("/api/v1/posts", func(r chi.Router) {
		r.Use(jwtMgr.JWTMiddleware)
		r.Post("/", postHdl.CreatePost)
	})

	return r
}
