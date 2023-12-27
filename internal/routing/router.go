package routing

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"server-alpha/internal/managers"
	"server-alpha/internal/routing/handlers"
	"time"
)

func InitRouter(pool *pgxpool.Pool) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(15 * time.Second))
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	// Initialize database manager
	databaseMgr := managers.NewDatabaseManager(pool)

	// Initialize mail manager
	mailMgr := managers.NewMailManager()

	// Initialize JWT manager
	jwtMgr, err := managers.NewJWTManager()
	if err != nil {
		panic(err)
	}

	// Initialize handlers
	userHdl := handlers.NewUserHandler(&databaseMgr, &jwtMgr, &mailMgr)
	postHdl := handlers.NewPostHandler(&databaseMgr)

	// Initialize user routes
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Post("/", userHdl.RegisterUser)
		r.Post("/login", userHdl.LoginUser)
		r.Post("/{username}/activate", userHdl.ActivateUser)
		r.Delete("/{username}/activate", userHdl.ResendToken)
	})

	// Initialize post routes
	r.Route("/api/v1/posts", func(r chi.Router) {
		r.Use(jwtMgr.JWTMiddleware)
		r.Post("/", postHdl.CreatePost)
	})

	return r
}
