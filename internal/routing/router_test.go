package routing

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/wwi21seb-projekt/server-alpha/internal/managers"
	"github.com/wwi21seb-projekt/server-alpha/internal/managers/mocks"
	"github.com/wwi21seb-projekt/server-alpha/internal/schemas"
	"net/http"
	"net/http/httptest"
	"regexp"
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
					"code":        "ERR-001",
					"http_status": 400,
					"message":     "The request body is invalid. Please check the request body and try again.",
					"title":       "BadRequest",
				},
			}},
		{
			"DuplicateUsername",
			createUserRequestWithDuplicateUsername(),
			http.StatusConflict,
			map[string]interface{}{
				"error": map[string]interface{}{
					"code":        "ERR-002",
					"http_status": 409,
					"message":     "The username is already taken. Please try another username.",
					"title":       "UsernameTaken",
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

			switch tc.name {
			case "InvalidEmail":
			case "DuplicateUsername":
				poolMock.ExpectBegin()
				poolMock.ExpectQuery("SELECT").WithArgs(tc.user.Username, tc.user.Email).WillReturnRows(pgxmock.NewRows([]string{"username", "email"}).AddRow(tc.user.Username, tc.user.Email))
			default:
				poolMock.ExpectBegin()
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

type MockDBCall struct {
	Query         string
	Args          []interface{}
	ReturnColumns []string
	ReturnValues  []interface{}
	Error         error
}

type testCaseStructureSubscription struct {
	name         string
	userId       string
	username     string
	jwtToken     string
	status       int
	responseBody map[string]interface{}
	dbCalls      []MockDBCall
}

func TestGetSubscriptions(t *testing.T) {
	userId := "1752e5cc-77a4-4913-9924-63a439654a8e"
	username := "testUser"

	// Define test cases
	testCases := []testCaseStructureSubscription{
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
			[]MockDBCall{
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
					"code":        "ERR-014",
					"http_status": 401,
					"message":     "The request is unauthorized. Please login to your account.",
					"title":       "Unauthorized",
				},
			},
			[]MockDBCall{},
		},
		{
			"User not found",
			userId,
			username,
			"",
			http.StatusNotFound,
			map[string]interface{}{
				"error": map[string]interface{}{
					"code":        "ERR-004",
					"http_status": 404,
					"message":     "The user was not found. Please check the username and try again.",
					"title":       "UserNotFound",
				},
			},
			[]MockDBCall{
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
					"code":        "ERR-014",
					"http_status": 401,
					"message":     "The request is unauthorized. Please login to your account.",
					"title":       "Unauthorized",
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
					"code":        "ERR-019",
					"http_status": 403,
					"message":     "You can only delete your own posts.",
					"title":       "DeletePostForbidden",
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
					"code":        "ERR-020",
					"http_status": 404,
					"message":     "The post was not found. Please check the post ID and try again.",
					"title":       "PostNotFound",
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

func TestCreateComment(t *testing.T) {
	userId := "c45f92c4-0d64-4e2e-9939-370ec8a9c61c"
	username := "testUser"
	postId := "3d6fa5c8-2e74-4d9c-9df2-5aeb6b59fcd5"

	testCases := []struct {
		name         string
		status       int
		jwtToken     string
		userId       string
		username     string
		postId       string
		content      schemas.CreateCommentRequest
		responseBody map[string]interface{}
	}{
		{
			"Success",
			http.StatusCreated,
			"",
			userId,
			username,
			postId,
			schemas.CreateCommentRequest{Content: "This is a test comment."},
			map[string]interface{}{
				"postId": "3d6fa5c8-2e74-4d9c-9df2-5aeb6b59fcd5",
				"author": map[string]interface{}{
					"nickname":          "Test User",
					"profilePictureURL": "",
					"username":          "test_user",
				},
				"content": "This is a test comment.",
			},
		},
		{
			"Unauthorized",
			http.StatusUnauthorized,
			"NonsenseToken",
			userId,
			username,
			postId,
			schemas.CreateCommentRequest{Content: "This is a test comment."},
			map[string]interface{}{
				"error": map[string]interface{}{
					"code":        "ERR-014",
					"http_status": 401,
					"message":     "The request is unauthorized. Please login to your account.",
					"title":       "Unauthorized",
				},
			},
		},
		{
			"Not Found",
			http.StatusNotFound,
			"",
			userId,
			username,
			postId,
			schemas.CreateCommentRequest{Content: "This is a test comment."},
			map[string]interface{}{
				"error": map[string]interface{}{
					"code":        "ERR-020",
					"http_status": 404,
					"message":     "The post was not found. Please check the post ID and try again.",
					"title":       "PostNotFound",
				},
			},
		},
		{
			"Bad Request",
			http.StatusBadRequest,
			"",
			userId,
			username,
			postId,
			schemas.CreateCommentRequest{Content: "This comment is too long. This comment is too long. This comment is too long. This comment is too long. This comment is too long. This comment is too long. This comment is too long. This comment is too long."},
			map[string]interface{}{
				"error": map[string]interface{}{
					"code":        "ERR-001",
					"http_status": 400,
					"message":     "The request body is invalid. Please check the request body and try again.",
					"title":       "BadRequest",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			databaseMgrMock, jwtManager, mailMgrMock := setupMocks(t)

			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManager)

			server := httptest.NewServer(router)
			defer server.Close()

			// Generate JWT token if not already set
			if tc.jwtToken == "" {
				tc.jwtToken, _ = jwtManager.GenerateJWT(tc.userId, tc.username, false)
			}

			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

			switch tc.name {
			case "Success":
				poolMock.ExpectBegin()
				// Expect the SELECT COUNT(*) query to check if the post exists
				poolMock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM alpha_schema.posts WHERE post_id = \\$1").
					WithArgs(tc.postId).
					WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

				// Expect the insert into comments table
				poolMock.ExpectExec("INSERT INTO alpha_schema.comments").
					WithArgs(pgxmock.AnyArg(), tc.postId, tc.userId, pgxmock.AnyArg(), tc.content.Content).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))

				// Expect the select from users table
				poolMock.ExpectQuery("SELECT username, nickname FROM alpha_schema.users WHERE user_id = \\$1").
					WithArgs(tc.userId).
					WillReturnRows(pgxmock.NewRows([]string{"username", "nickname"}).AddRow("test_user", "Test User"))

				poolMock.ExpectCommit()
			case "Not Found":
				poolMock.ExpectBegin()
				// Expect the SELECT COUNT(*) query to check if the post exists
				poolMock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM alpha_schema.posts WHERE post_id = \\$1").
					WithArgs(tc.postId).
					WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
			}

			expect := httpexpect.Default(t, server.URL)
			request := expect.POST(fmt.Sprintf("/api/posts/%s/comments", tc.postId)).WithJSON(tc.content).WithHeader("Authorization", "Bearer "+tc.jwtToken)
			response := request.Expect().Status(tc.status)
			response.JSON().IsEqual(tc.responseBody)

			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestGetComments(t *testing.T) {
	postId := "1d4d2079-0423-4f8e-b063-8cf97553c306"
	userId := "1752e5cc-77a4-4913-9924-63a439654a8e"
	username := "testUser"

	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		fmt.Println("Error loading location:", err)
		return
	}

	// Define test cases
	testCases := []struct {
		name         string
		postId       string
		status       int
		responseBody map[string]interface{}
		dbCalls      []MockDBCall
	}{
		{
			"Success",
			postId,
			http.StatusOK,
			map[string]interface{}{
				"records": []map[string]interface{}{
					{
						"commentId": "67d701e4-6b10-4806-8f68-767d32f2aceb",
						"content":   "This is a test comment",
						"author": map[string]interface{}{
							"username":          "testUser",
							"nickname":          "",
							"profilePictureURL": "",
						},
						"creationDate": time.Date(2024, 05, 20, 20, 50, 28, 0, loc),
					},
				},
				"pagination": map[string]interface{}{
					"offset": 0,
					"limit":  10,
				},
			},
			[]MockDBCall{
				{
					Query:         "SELECT COUNT(*) FROM alpha_schema.posts WHERE post_id = $1",
					Args:          []interface{}{postId},
					ReturnColumns: []string{"count"},
					ReturnValues:  []interface{}{1},
				},
				{
					Query:         "SELECT c.comment_id, c.content, c.created_at, u.username, u.nickname FROM alpha_schema.comments AS c JOIN alpha_schema.users AS u ON c.author_id = u.user_id WHERE c.post_id = $1 ORDER BY c.created_at DESC LIMIT $2 OFFSET $3",
					Args:          []interface{}{postId, 10, 0},
					ReturnColumns: []string{"comment_id", "content", "created_at", "username", "nickname"},
					ReturnValues:  []interface{}{"67d701e4-6b10-4806-8f68-767d32f2aceb", "This is a test comment", time.Date(2024, 05, 20, 20, 50, 28, 0, loc), "testUser", ""},
				},
			},
		},
		{
			"NoComments",
			postId,
			http.StatusOK,
			map[string]interface{}{
				"records": []map[string]interface{}{},
				"pagination": map[string]interface{}{
					"offset": 0,
					"limit":  10,
				},
			},
			[]MockDBCall{
				{
					Query:         "SELECT COUNT(*) FROM alpha_schema.posts WHERE post_id = $1",
					Args:          []interface{}{postId},
					ReturnColumns: []string{"count"},
					ReturnValues:  []interface{}{1},
				},
				{
					Query:         "SELECT c.comment_id, c.content, c.created_at, u.username, u.nickname FROM alpha_schema.comments AS c JOIN alpha_schema.users AS u ON c.author_id = u.user_id WHERE c.post_id = $1 ORDER BY c.created_at DESC LIMIT $2 OFFSET $3",
					Args:          []interface{}{postId, 10, 0},
					ReturnColumns: []string{"comment_id", "content", "created_at", "username", "nickname"},
					ReturnValues:  nil,
				},
			},
		},
		{
			"PostNotFound",
			postId,
			http.StatusNotFound,
			map[string]interface{}{
				"error": map[string]interface{}{
					"code":        "ERR-020",
					"http_status": 404,
					"message":     "The post was not found. Please check the post ID and try again.",
					"title":       "PostNotFound",
				},
			},
			[]MockDBCall{
				{
					Query:         "SELECT COUNT(*) FROM alpha_schema.posts WHERE post_id = $1",
					Args:          []interface{}{postId},
					ReturnColumns: []string{"count"},
					ReturnValues:  []interface{}{0},
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

			jwtToken, _ := jwtManager.GenerateJWT(userId, username, false)

			// Get mock pool
			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)
			poolMock.ExpectBegin()

			// Mock database calls
			for _, mock := range tc.dbCalls {
				if mock.Query != "" {
					if mock.Error != nil {
						poolMock.ExpectQuery(regexp.QuoteMeta(mock.Query)).WithArgs(mock.Args...).WillReturnError(mock.Error)
					} else {
						rows := pgxmock.NewRows(mock.ReturnColumns)
						if mock.ReturnValues != nil {
							rows.AddRow(mock.ReturnValues...)
						}
						poolMock.ExpectQuery(regexp.QuoteMeta(mock.Query)).WithArgs(mock.Args...).WillReturnRows(rows)
					}
				}
			}

			// Create request and get response
			expect := httpexpect.Default(t, server.URL)
			request := expect.GET(fmt.Sprintf("/api/posts/%s/comments", tc.postId)).WithQuery("offset", 0).WithQuery("limit", 10).WithHeader("Authorization", "Bearer "+jwtToken)
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
