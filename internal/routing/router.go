package routing

import (
	"net/http"
	"os"
	"server-alpha/internal/handlers"
	"server-alpha/internal/managers"
	"server-alpha/internal/middleware"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var imprintDto = &schemas.ImprintDTO{
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

func InitRouter(databaseMgr managers.DatabaseMgr, mailMgr managers.MailMgr, jwtMgr managers.JWTMgr) *gin.Engine {
	// Initialize router with logging and recovery middleware
	router := gin.New()
	// Initialize middleware
	setupCommonMiddleware(router)
	// Setup routes
	setupRoutes(router, databaseMgr, mailMgr, jwtMgr)

	return router
}

func setupCommonMiddleware(router *gin.Engine) {
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.InjectTrace())
	router.Use(cors.New(cors.Config{
		AllowOrigins:  []string{"http://localhost:5173", "http://localhost:19000"},
		AllowMethods:  []string{"GET", "PATCH", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:  []string{"Accept, Authorization", "Content-Type"},
		ExposeHeaders: []string{"Content-Length", "Content-Type", "X-Correlation-ID"},
		MaxAge:        12 * time.Hour,
	}))
	router.Use(func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
	})
	router.Use(middleware.SanitizePath())
	router.Use(middleware.LogRequest())
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
		utils.WriteAndLogResponse(c, metadata, http.StatusOK)
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
		apiRouter.GET("/imprint", func(c *gin.Context) {
			utils.WriteAndLogResponse(c, imprintDto, http.StatusOK)
		})

		// Set up user routes
		userRouter := apiRouter.Group("/users")
		userHdl := handlers.NewUserHandler(&databaseMgr, &jwtMgr, &mailMgr)
		userRoutes(userRouter, userHdl, jwtMgr)

		// Set up post routes
		postRouter := apiRouter.Group("/posts")
		postHdl := handlers.NewPostHandler(&databaseMgr, &jwtMgr)
		// It's important to define the feed route prior to the post routes, because
		// we don't want the JWT middleware in this unauthorized request
		apiRouter.GET("/feed", postHdl.HandleGetFeedRequest)
		postRoutes(postRouter, postHdl, jwtMgr)

		// Set up subscription routes
		subscriptionsRouter := apiRouter.Group("/subscriptions")
		subscriptionsRouter.Use(jwtMgr.JWTMiddleware())
		subscriptionHdl := handlers.NewSubscriptionHandler(&databaseMgr)
		subscriptionsRoutes(subscriptionsRouter, subscriptionHdl)
	}
}

func userRoutes(userRouter *gin.RouterGroup, userHdl handlers.UserHdl, jwtMgr managers.JWTMgr) {
	userRouter.POST("/", middleware.ValidateAndSanitizeStruct(&schemas.RegistrationRequest{}), userHdl.RegisterUser)
	userRouter.POST("/login", middleware.ValidateAndSanitizeStruct(&schemas.LoginRequest{}), userHdl.LoginUser)
	userRouter.POST("/refresh", middleware.ValidateAndSanitizeStruct(&schemas.RefreshTokenRequest{}), userHdl.RefreshToken)
	userRouter.POST("/:username/activate", middleware.ValidateAndSanitizeStruct(&schemas.ActivationRequest{}), userHdl.ActivateUser)
	userRouter.DELETE("/:username/activate", userHdl.ResendToken)
	userRouter.GET("/:username/feed", userHdl.RetrieveUserPosts)
	// The following routes require the user to be authenticated
	userRouter.Use(jwtMgr.JWTMiddleware())
	userRouter.GET("/:username", userHdl.HandleGetUserRequest)
	userRouter.GET("/", userHdl.SearchUsers)
	userRouter.PATCH("/", middleware.ValidateAndSanitizeStruct(&schemas.ChangePasswordRequest{}), userHdl.ChangePassword)
	userRouter.PUT("/", middleware.ValidateAndSanitizeStruct(&schemas.ChangeTrivialInformationRequest{}), userHdl.ChangeTrivialInformation)
}

func postRoutes(postRouter *gin.RouterGroup, postHdl handlers.PostHdl, jwtMgr managers.JWTMgr) {
	postRouter.Use(jwtMgr.JWTMiddleware())
	postRouter.POST("/", middleware.ValidateAndSanitizeStruct(&schemas.CreatePostRequest{}), postHdl.CreatePost)
	postRouter.GET("/", postHdl.QueryPosts)
	postRouter.DELETE("/:postId", postHdl.DeletePost)
}

func subscriptionsRoutes(subscriptionsRouter *gin.RouterGroup, subscriptionHdl handlers.SubscriptionHdl) {
	subscriptionsRouter.POST("/", middleware.ValidateAndSanitizeStruct(&schemas.SubscriptionRequest{}), subscriptionHdl.Subscribe)
	subscriptionsRouter.DELETE("/:subscriptionId", subscriptionHdl.Unsubscribe)
	subscriptionsRouter.GET("/:username", subscriptionHdl.HandleGetSubscriptions)
}
