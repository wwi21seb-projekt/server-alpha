package routing

import (
	"net/http"
	"os"
	"server-alpha/internal/managers"
	"server-alpha/internal/middleware"
	"server-alpha/internal/schemas"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var imprintDto = schemas.ImprintDTO{
	Text: "Impressum\n\nEinen Löwen interessiert es nicht, was Schafe über ihn denken.\n\nDiese Webseite " +
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
		"ausschließlich zu nicht-kommerziellen Zwecken.",
}

func InitRouter2(databaseMgr managers.DatabaseMgr, mailMgr managers.MailMgr, jwtMgr managers.JWTMgr) *gin.Engine {
	// Initialize router with logging and recovery middleware
	router := gin.New()
	// Initialize middleware
	setupCommonMiddleware(router)
	// Set up routes
	setupRoutes(router, databaseMgr, mailMgr, jwtMgr)

	return router
}

func setupCommonMiddleware(router *gin.Engine) {
	router.Use(middleware.InjectTrace())
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(cors.New(cors.Config{
		AllowOrigins:  []string{"http://localhost:5173", "http://localhost:19000"},
		AllowMethods:  []string{"GET", "PATCH", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:  []string{"Accept, Authorization", "Content-Type", "Origin"},
		ExposeHeaders: []string{"Content-Length", "Content-Type", "X-Correlation-ID"},
		MaxAge:        12 * time.Hour,
	}))
	router.Use
}

func setupRoutes(router *gin.Engine, databaseMgr managers.DatabaseMgr, mailMgr managers.MailMgr, jwtMgr managers.JWTMgr) {
	// Set up version route
	router.GET("/", func(c *gin.Context) {
		apiVersion := os.Getenv("PR_NUMBER")
		var pullRequest string

		if apiVersion == "" {
			apiVersion = "main:latest"
		} else {
			pullRequest = "https://github.com/wwi21seb-projekt/server-alpha/pull/" + apiVersion
			apiVersion = "PR-" + apiVersion
		}
		metadata := &schemas.MetadataDTO{
			ApiVersion:  apiVersion,
			ApiName:     "Server Alpha",
			PullRequest: pullRequest,
		}
		c.JSON(http.StatusOK, metadata)
	})

	// Set up health route
	router.GET("/health", func(c *gin.Context) {
		// Ping the database
		conn, err := databaseMgr.GetPool().Acquire(c)
		defer conn.Release()
		if err != nil {
			c.String(http.StatusInternalServerError, "Database not responding")
			return
		}
		c.Status(http.StatusOK)
	})

	// Set up API routes
	apiRouter := router.Group("/api")
	{
		// Set up imprint route
		api.GET("/imprint", func(c *gin.Context) {
			c.JSON(http.StatusOK, imprintDto)
		})

		// Set up user routes
		users := api.Group("/users")
		userRoutes(users, databaseMgr, mailMgr, jwtMgr)

		// Set up feed routes
		feed := api.Group("/feed")
		feedRoutes(feed, databaseMgr, jwtMgr)

		// Set up post routes
		posts := api.Group("/posts")
		posts.Use(jwtMgr.JWTMiddleware())
		postRoutes(posts, databaseMgr, jwtMgr)

		// Set up subscription routes
		subscriptions := api.Group("/subscriptions")
		subscriptionRoutes(api, subscriptions, databaseMgr, jwtMgr)
	}

	func userRoutes(apiRouter *gin.RouterGroup, databaseMgr managers.DatabaseMgr, mailMgr managers.MailMgr, jwtMgr managers.JWTMgr) {

	}
}
