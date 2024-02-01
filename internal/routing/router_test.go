package routing

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"server-alpha/internal/managers"
	"server-alpha/internal/managers/mocks"
	"testing"

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
