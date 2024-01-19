package routing

import (
	"github.com/go-chi/cors"
	"net/http"
	"server-alpha/internal/handlers"
	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func InitRouter(databaseMgr managers.DatabaseMgr, mailMgr managers.MailMgr, jwtMgr managers.JWTMgr) *chi.Mux {
	r := chi.NewRouter()

	// Configure CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"http://localhost:5173", "http://localhost:19000"},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type"},
		MaxAge:         300,
	}))
	// Inject request ID into context
	r.Use(middleware.RequestID)
	// Add logger to middleware stack
	r.Use(middleware.Logger)
	// Add recoverer to middleware stack
	r.Use(middleware.Recoverer)
	// Set base timeout for all requests to 15 seconds
	r.Use(middleware.Timeout(15 * time.Second))
	// Set content type to JSON
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	// Initialize handlers
	postHdl := handlers.NewPostHandler(&databaseMgr, &jwtMgr)

	// Initialize subscription handlers
	subscriptionHdl := handlers.NewSubscriptionHandler(&databaseMgr)

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

	r.Get("/api/imprint", func(w http.ResponseWriter, r *http.Request) {
		imprint := "Impressum\n\nEinen Löwen interessiert es nicht, was Schafe über ihn denken.\n\nDiese Webseite " +
			"wird im Rahmen eines Universitätsprojektes angeboten von:\nKurs WWI21SEB\nDuale Hochschule " +
			"Baden-Württemberg Mannheim\nCoblitzallee 1 – 9, 68163 Mannheim\n\nKontakt:\nE-Mail: " +
			"team@mail.server-alpha.tech\n\nHaftungsausschluss:\nDer Kurs WWI21SEB und die DHBW Mannheim übernehmen " +
			"keine Haftung für die Inhalte externer Links. Für den Inhalt der verlinkten Seiten sind ausschließlich " +
			"deren Betreiber verantwortlich.\n\nDatenschutzbeauftragter der Hochschule:\nProf. Dr. Tobias Straub\n" +
			"Friedrichstraße 14\n70174 Stuttgart\nE-Mail: straub@dhbw.de\n\nDie Nutzung von auf dieser Website " +
			"veröffentlichten Kontaktdaten durch Dritte zur Übersendung von nicht ausdrücklich angeforderter Werbung " +
			"und Informationsmaterialien wird hiermit ausdrücklich untersagt. Die Betreiber der Seiten behalten sich " +
			"ausdrücklich rechtliche Schritte im Falle der unverlangten Zusendung von Werbeinformationen, etwa durch " +
			"Spam-Mails, vor.\n\nDiese Webseite wurde im Rahmen eines Universitätsprojekts erstellt und dient " +
			"ausschließlich zu nicht-kommerziellen Zwecken."

		imprintDto := &schemas.ImprintDTO{
			Text: imprint,
		}

		utils.WriteAndLogResponse(w, imprintDto, http.StatusOK)
	})

	// Initialize user routes
	r.Route("/api/users", userRouter(&databaseMgr, jwtMgr, &mailMgr))

	// Initialize feed routes
	r.Route("/api/feed", func(r chi.Router) {
		r.Get("/", postHdl.HandleGetFeedRequest)
	})

	// Initialize post routes
	r.Route("/api/posts", func(r chi.Router) {
		r.Use(jwtMgr.JWTMiddleware)
		r.Post("/", postHdl.CreatePost)
		r.Delete("/{postId}", postHdl.DeletePost)
	})

	// Intialize subscription routes
	r.Route("/api/subscriptions", func(r chi.Router) {
		r.Use(jwtMgr.JWTMiddleware)
		r.Post("/", subscriptionHdl.Subscribe)
		r.Delete("/{subscriptionId}", subscriptionHdl.Unsubscribe)
		r.Get("/", subscriptionHdl.HandleGetSubscriptions)
	})

	return r
}

func userRouter(databaseMgr *managers.DatabaseMgr, jwtMgr managers.JWTMgr, mailMgr *managers.MailMgr) func(chi.Router) {
	return func(r chi.Router) {
		userHdl := handlers.NewUserHandler(databaseMgr, &jwtMgr, mailMgr)

		r.Post("/", userHdl.RegisterUser)
		r.With(jwtMgr.JWTMiddleware).Get("/", userHdl.SearchUsers)
		r.With(jwtMgr.JWTMiddleware).Put("/", userHdl.ChangeTrivialInformation)
		r.With(jwtMgr.JWTMiddleware).Patch("/", userHdl.ChangePassword)
		r.Post("/login", userHdl.LoginUser)
		r.Post("/refresh", userHdl.RefreshToken)
		r.Post("/{username}/activate", userHdl.ActivateUser)
		r.Delete("/{username}/activate", userHdl.ResendToken)
		r.With(jwtMgr.JWTMiddleware).Get("/{username}", userHdl.HandleGetUserRequest)
		r.Get("/{username}/feed", userHdl.RetrieveUserPosts)
	}
}
