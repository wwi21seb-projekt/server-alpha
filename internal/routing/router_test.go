package routing

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"regexp"
	"server-alpha/internal/managers"
	"server-alpha/internal/managers/mocks"
	"strconv"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// define request payload for user registration
type User struct {
	UserId         string `json:"user_id"`
	Username       string `json:"username"`
	Nickname       string `json:"nickname"`
	Password       string `json:"password"`
	HashedPassword string `json:"hashed_password"`
	Email          string `json:"email"`
}

type MockDBCallSelect struct {
	Query         string
	Args          []interface{}
	ReturnColumns []string
	ReturnValues  []interface{}
}

func setupMocks(t *testing.T) (*mocks.MockDatabaseManager, managers.JWTMgr, *mocks.MockMailManager) {
	poolMock, err := pgxmock.NewPool()
	if err != nil {
		log.Errorf("Error creating mock database pool: %v", err)
	}

	databaseMgrMock := &mocks.MockDatabaseManager{}
	databaseMgrMock.On("GetPool").Return(poolMock)

	t.Setenv("ENVIRONMENT", "test")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Errorf("Error generating key pair: %v", err)
	}
	jwtMgr := managers.NewJWTManager(privateKey, publicKey)

	mailMgrMock := &mocks.MockMailManager{}
	mailMgrMock.On("SendActivationMail", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)

	return databaseMgrMock, jwtMgr, mailMgrMock
}

// TODO add tests for other routes
func TestUserRegistration(t *testing.T) {

	createUserRequest := func() User {
		return User{
			Username: "testUser",
			Nickname: "testNickname",
			Password: "test.Password123",
			Email:    "test@example.com",
		}
	}

	createUserRequestWithInvalidEmail := func() User {
		return User{
			Username: "testUser",
			Nickname: "testNickname",
			Password: "test.Password123",
			Email:    "test@example@.com",
		}
	}

	createUserRequestWithDuplicateUsername := func() User {
		return User{
			Username: "duplicateUser",
			Nickname: "duplicateNickname",
			Password: "duplicate.Password123",
			Email:    "duplicate@example.com",
		}
	}

	testCases := []struct {
		name         string
		user         User
		status       int
		responseBody map[string]interface{}
	}{
		{
			"ValidRegistration",
			createUserRequest(),
			http.StatusCreated,
			map[string]interface{}{
				"username": "testUser",
				"nickname": "testNickname",
				"email":    "test@example.com",
			},
		},
		{
			"InvalidEmail",
			createUserRequestWithInvalidEmail(),
			http.StatusBadRequest,
			map[string]interface{}{
				"error": map[string]interface{}{
					"code":    "ERR-001",
					"message": "The request body is invalid. Please check the request body and try again.",
				},
			}},
		{
			"DuplicateUsername",
			createUserRequestWithDuplicateUsername(),
			http.StatusConflict,
			map[string]interface{}{
				"error": map[string]interface{}{
					"code":    "ERR-002",
					"message": "The username is already taken. Please try another username.",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			databaseMgrMock, jwtManagerMock, mailMgrMock := setupMocks(t)

			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManagerMock)

			server := httptest.NewServer(router)
			defer server.Close()

			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

			// Mock database calls
			poolMock.ExpectBegin()

			switch tc.name {
			case "InvalidEmail":
			case "DuplicateUsername":
				poolMock.ExpectQuery("SELECT").WithArgs(tc.user.Username, tc.user.Email).WillReturnRows(pgxmock.NewRows([]string{"username", "email"}).AddRow(tc.user.Username, tc.user.Email))
			default:
				poolMock.ExpectQuery("SELECT").WithArgs(tc.user.Username, tc.user.Email).WillReturnRows(pgxmock.NewRows([]string{"username", "email"}))
				poolMock.ExpectExec("INSERT").WithArgs(pgxmock.AnyArg(), tc.user.Username, tc.user.Nickname, tc.user.Email, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), "", "").WillReturnResult(pgxmock.NewResult("INSERT", 1))
				poolMock.ExpectExec("DELETE").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("DELETE", 0))
				poolMock.ExpectExec("INSERT").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
				poolMock.ExpectCommit()
			}

			// Assert that the response status code is 201 and the response body contains the expected values
			expect := httpexpect.Default(t, server.URL)
			request := expect.POST("/api/users").WithJSON(tc.user)
			response := request.Expect().Status(tc.status)
			response.JSON().IsEqual(tc.responseBody)

			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestUserLogin(t *testing.T) {
	createLoginRequest := func() User {
		u := User{
			UserId:   uuid.New().String(),
			Username: "testUser",
			Password: "test.Password123",
		}

		hash, _ := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		u.HashedPassword = string(hash)

		return u
	}

	testCases := []struct {
		name         string
		user         User
		status       int
		responseBody map[string]interface{}
	}{
		{
			"ValidLogin",
			createLoginRequest(),
			http.StatusOK,
			map[string]interface{}{
				"username": "testUser",
				"nickname": "testNickname",
				"email":    "test@example.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			databaseMgrMock, jwtManagerMock, mailMgrMock := setupMocks(t)

			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManagerMock)

			server := httptest.NewServer(router)
			defer server.Close()

			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

			// Mock database calls
			poolMock.ExpectBegin()
			poolMock.ExpectQuery("SELECT activated_at").WithArgs(tc.user.Username).WillReturnRows(pgxmock.NewRows([]string{"activated_at"}).AddRow("2006-01-02 15:04:05.999999999Z"))
			poolMock.ExpectQuery("SELECT password, user_id").WithArgs(tc.user.Username).WillReturnRows(pgxmock.NewRows([]string{"password", "user_id"}).AddRow(tc.user.HashedPassword, tc.user.UserId))
			poolMock.ExpectQuery("SELECT email, user_id").WithArgs(tc.user.Username).WillReturnRows(pgxmock.NewRows([]string{"email", "user_id"}).AddRow(tc.user.Email, tc.user.UserId))
			poolMock.ExpectCommit()

			// Assert that the response status code is 200 and the response body contains the expected values
			expect := httpexpect.Default(t, server.URL)
			request := expect.POST("/api/users/login").WithJSON(tc.user)
			request.Expect().Status(tc.status)

			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestImprint(t *testing.T) {

	testCases := []struct {
		name         string
		status       int
		responseBody map[string]interface{}
	}{
		{
			"Sucessful",
			http.StatusOK,
			map[string]interface{}{
				"text": "Impressum\n\nEinen Löwen interessiert es nicht, was Schafe über ihn denken.\n\nDiese Webseite " +
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
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks
			databaseMgrMock, jwtManager, mailMgrMock := setupMocks(t)

			// Initialize router
			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManager)

			// Create test server
			server := httptest.NewServer(router)
			defer server.Close()

			// Get mock pool
			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

			// Mock database calls

			// Create request and get response
			expect := httpexpect.Default(t, server.URL)
			request := expect.GET("/api/imprint")
			response := request.Expect().Status(tc.status)

			// Assert response
			response.JSON().IsEqual(tc.responseBody)
			// Check if all expectations were met
			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestGetSubscriptions(t *testing.T) {
	userId := "1752e5cc-77a4-4913-9924-63a439654a8e"
	username := "testUser"

	// Define test cases
	testCases := []struct {
		name         string
		userId       string
		username     string
		jwtToken     string
		status       int
		responseBody map[string]interface{}
		dbCalls      []MockDBCallSelect
	}{
		{
			"Successful",
			userId,
			username,
			"",
			http.StatusOK,
			map[string]interface{}{
				"records": []map[string]interface{}{
					{
						"followerId":        "dad19145-7a7d-4656-a2ae-5092cf543ec8",
						"followingId":       userId,
						"username":          "testo",
						"nickname":          "testi",
						"profilePictureUrl": "/testUrl/",
					},
				},
				"pagination": map[string]interface{}{
					"limit":   10,
					"offset":  0,
					"records": 1,
				},
			},
			[]MockDBCallSelect{
				{
					Query:         "SELECT",
					Args:          []interface{}{username},
					ReturnColumns: []string{"username"},
					ReturnValues:  []interface{}{username},
				},
				{
					Query: `
						SELECT s2.subscription_id, s3.subscription_id, u.username,u.nickname, u.profile_picture_url
						FROM alpha_schema.users
						AS u JOIN alpha_schema.subscriptions
						AS s1 ON u.user_id = s1.subscriber_id LEFT JOIN alpha_schema.subscriptions
						AS s2 ON u.user_id = s2.subscribee_id AND s2.subscriber_id = $1 LEFT JOIN alpha_schema.subscriptions
						AS s3 ON u.user_id = s3.subscriber_id AND s3.subscribee_id = $1
						WHERE s1.subscribee_id = (SELECT user_id FROM alpha_schema.users WHERE username = $2)
						ORDER BY s1.created_at DESC
						`,
					Args:          []interface{}{userId, username},
					ReturnColumns: []string{"followerId", "followingId", "username", "nickname", "profile_picture_url"},
					ReturnValues: []interface{}{
						userId,
						"dad19145-7a7d-4656-a2ae-5092cf543ec8",
						"testo",
						"testi",
						"/testUrl/",
					},
				},
				{
					Query:         `SELECT COUNT(*) FROM alpha_schema.subscriptions s WHERE s.subscribee_id = (SELECT user_id FROM alpha_schema.users WHERE username = $1)`,
					Args:          []interface{}{username},
					ReturnColumns: []string{"count"},
					ReturnValues:  []interface{}{1},
				},
			},
		},
		{
			"Unauthorized",
			userId,
			username,
			"NonsenseToken",
			http.StatusUnauthorized,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The request is unauthorized. Please login to your account.",
					"code":    "ERR-014",
				},
			},
			[]MockDBCallSelect{},
		},
		{
			"User not found",
			userId,
			username,
			"",
			http.StatusNotFound,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The user was not found. Please check the username and try again.",
					"code":    "ERR-004",
				},
			},
			[]MockDBCallSelect{
				{
					Query:         "SELECT",
					Args:          []interface{}{username},
					ReturnColumns: []string{"username"},
					ReturnValues:  []interface{}{},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks
			databaseMgrMock, jwtManager, mailMgrMock := setupMocks(t)

			// Initialize router
			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManager)

			// Create test server
			server := httptest.NewServer(router)
			defer server.Close()

			// Generate JWT token if not already set
			if tc.jwtToken == "" {
				tc.jwtToken, _ = jwtManager.GenerateJWT(tc.userId, tc.username, false)
			}

			// Get mock pool
			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

			// Mock database calls
			for _, mock := range tc.dbCalls {
				if mock.Query != "" {
					rows := pgxmock.NewRows(mock.ReturnColumns)
					if len(mock.ReturnValues) == len(mock.ReturnColumns) {
						rows.AddRow(mock.ReturnValues...)
					}
					poolMock.ExpectQuery(regexp.QuoteMeta(mock.Query)).WithArgs(mock.Args...).WillReturnRows(rows)
				}
			}

			// Create request and get response
			expect := httpexpect.Default(t, server.URL)
			request := expect.GET("/api/subscriptions/"+tc.username).WithHeader("Authorization", "Bearer "+tc.jwtToken)
			response := request.Expect().Status(tc.status)

			// Assert response
			response.JSON().IsEqual(tc.responseBody)

			// Check if all expectations were met
			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestDeletePost(t *testing.T) {
	userId := "1752e5cc-77a4-4913-9924-63a439654a8e"
	username := "testUser"
	postId := "4d9e0a1d-faa6-473d-a5cb-fadabb2db590"

	testCases := []struct {
		name         string
		status       int
		userId       string
		username     string
		postId       string
		responseBody map[string]interface{}
	}{
		{
			"SucessfulDelete",
			http.StatusNoContent,
			userId,
			username,
			postId,
			nil,
		},
		{
			"UnauthoriedDelete",
			http.StatusUnauthorized,
			"",
			"",
			postId,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The request is unauthorized. Please login to your account.",
					"code":    "ERR-014",
				},
			},
		},
		{
			"ForbiddenDelete",
			http.StatusForbidden,
			userId,
			username,
			postId,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "You can only delete your own posts.",
					"code":    "ERR-019",
				},
			},
		},
		{
			"PostNotFound",
			http.StatusNotFound,
			userId,
			username,
			postId,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The post was not found. Please check the post ID and try again.",
					"code":    "ERR-020",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks
			databaseMgrMock, jwtManager, mailMgrMock := setupMocks(t)

			// Initialize router
			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManager)

			// Create test server
			server := httptest.NewServer(router)
			defer server.Close()

			// Generate JWT token if user is logged in
			jwtToken := ""
			if tc.userId == "" && tc.username == "" {
				jwtToken = "invalidToken"
			} else {
				jwtToken, _ = jwtManager.GenerateJWT(tc.userId, tc.username, false)
			}

			// Get mock pool
			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

			// Mock database calls

			switch tc.name {
			case "SucessfulDelete":
				poolMock.ExpectBegin()
				poolMock.ExpectQuery("SELECT author_id, content FROM alpha_schema.posts").WithArgs(tc.postId).WillReturnRows(pgxmock.NewRows([]string{"author_id", "content"}).AddRow(tc.userId, "#test"))
				poolMock.ExpectExec("DELETE FROM alpha_schema.posts").WithArgs(tc.postId).WillReturnResult(pgxmock.NewResult("DELETE", 1))
				poolMock.ExpectExec("DELETE FROM alpha_schema.hashtags").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("DELETE", 1))
				poolMock.ExpectCommit()
			case "ForbiddenDelete":
				poolMock.ExpectBegin()
				poolMock.ExpectQuery("SELECT author_id, content FROM alpha_schema.posts").WithArgs(tc.postId).WillReturnRows(pgxmock.NewRows([]string{"author_id", "content"}).AddRow("", "#test"))
			case "PostNotFound":
				poolMock.ExpectBegin()
				poolMock.ExpectQuery("SELECT author_id, content FROM alpha_schema.posts").WithArgs(tc.postId).WillReturnRows(pgxmock.NewRows([]string{"author_id", "content"}))
			}

			// Create request and get response
			expect := httpexpect.Default(t, server.URL)
			request := expect.DELETE("/api/posts/"+tc.postId).WithHeader("Authorization", "Bearer "+jwtToken)
			response := request.Expect().Status(tc.status)

			// Assert response
			if response.Raw().StatusCode != http.StatusNoContent {
				response.JSON().IsEqual(tc.responseBody)
			}

			// Check if all expectations were met
			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestQueryPosts(t *testing.T) {
	userId := "1752e5cc-77a4-4913-9924-63a439654a8e"
	username := "testUser"
	hashtag := "alpha"
	limit := 10

	// Define test cases
	testCases := []struct {
		name         string
		userId       string
		username     string
		hashtag      string
		limit        int
		status       int
		responseBody map[string]interface{}
	}{
		{
			"Successful",
			userId,
			username,
			hashtag,
			limit,
			http.StatusOK,
			map[string]interface{}{
				"records": []map[string]interface{}{
					{
						"postId": "dad19145-7a7d-4656-a2ae-5092cf543ec8",
						"author": map[string]interface{}{
							"username":          "testAuthor",
							"nickname":          "author Nickname",
							"profilePictureURL": "/testUrl/",
						},
						"creationDate": "2021-01-01T00:00:00Z",
						"content":      "test content",
						"location": map[string]interface{}{
							"longitude": -77.0364,
							"latitude":  38.8951,
							"accuracy":  100,
						},
					},
				},
				"pagination": map[string]interface{}{
					"lastPostId": "dad19145-7a7d-4656-a2ae-5092cf543ec8",
					"limit":      "10",
					"records":    1,
				},
			},
		},
		{
			"Unauthorized",
			"",
			"",
			hashtag,
			limit,
			http.StatusUnauthorized,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The request is unauthorized. Please login to your account.",
					"code":    "ERR-014",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks
			databaseMgrMock, jwtManager, mailMgrMock := setupMocks(t)

			// Initialize router
			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManager)

			// Create test server
			server := httptest.NewServer(router)
			defer server.Close()

			// Generate JWT token if not already set
			jwtToken := ""
			if tc.userId == "" && tc.username == "" {
				jwtToken = "invalidToken"
			} else {
				jwtToken, _ = jwtManager.GenerateJWT(tc.userId, tc.username, false)
			}

			// Get mock pool
			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)
			if tc.name == "Successful" {
				// Mock database calls
				poolMock.ExpectBegin()
				poolMock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(DISTINCT posts.post_id) FROM alpha_schema.posts INNER JOIN alpha_schema.users ON author_id = user_id INNER JOIN alpha_schema.many_posts_has_many_hashtags ON post_id = post_id_posts INNER JOIN alpha_schema.hashtags ON hashtag_id = hashtag_id_hashtags WHERE hashtags.content LIKE $1")).WithArgs("%" + tc.hashtag + "%").WillReturnRows(pgxmock.NewRows([]string{"COUNT(DISTINCT posts.post_id)"}).AddRow(1))
				poolMock.ExpectQuery(regexp.QuoteMeta("SELECT DISTINCT posts.post_id, username, nickname, profile_picture_url, posts.content, posts.created_at, posts.longitude, posts.latitude, posts.accuracy FROM alpha_schema.posts INNER JOIN alpha_schema.users ON author_id = user_id INNER JOIN alpha_schema.many_posts_has_many_hashtags ON post_id = post_id_posts INNER JOIN alpha_schema.hashtags ON hashtag_id = hashtag_id_hashtags WHERE hashtags.content LIKE $1 ORDER BY created_at DESC LIMIT $2")).WithArgs("%"+tc.hashtag+"%", strconv.Itoa(limit)).WillReturnRows(pgxmock.NewRows([]string{"posts.post_id", "username", "nickname", "profile_picture_url", "posts.content", "posts.created_at", "posts.longitude", "posts.latitude", "posts.accuracy"}).AddRow("dad19145-7a7d-4656-a2ae-5092cf543ec8", "testAuthor", "author Nickname", "/testUrl/", "test content", func() time.Time {
					t, _ := time.Parse(time.RFC3339, "2021-01-01T00:00:00Z")
					return t
				}(), "-77.0364", "38.8951", "100"))
				poolMock.ExpectCommit()
			}

			// Create request and get response
			expect := httpexpect.Default(t, server.URL)
			request := expect.GET("/api/posts").WithQueryString("q="+tc.hashtag+"&limit="+strconv.Itoa(tc.limit)).WithHeader("Authorization", "Bearer "+jwtToken)
			response := request.Expect().Status(tc.status)
			// Assert response
			response.JSON().IsEqual(tc.responseBody)

			// Check if all expectations were met
			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}
