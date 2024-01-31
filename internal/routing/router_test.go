package routing

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"regexp"
	"server-alpha/internal/managers"
	"server-alpha/internal/managers/mocks"
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

type testCaseStructureSubscription struct {
	name         string
	userId       string
	username     string
	status       int
	responseBody map[string]interface{}
}

type MockDBCall struct {
	Query         string
	Args          []interface{}
	ReturnColumns []string
	ReturnValues  []interface{}
}

func runSubscriptionTestCase(t *testing.T, tc testCaseStructureSubscription, dbCalls []MockDBCall) {
	// Setup mocks
	databaseMgrMock, jwtManager, mailMgrMock := setupMocks(t)

	// Initialize router
	router := InitRouter(databaseMgrMock, mailMgrMock, jwtManager)

	// Create test server
	server := httptest.NewServer(router)
	defer server.Close()

	// Generate JWT token
	jwtToken, _ := jwtManager.GenerateJWT(tc.userId, tc.username, false)

	// Get mock pool
	poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

	// Mock database calls
	for _, mock := range dbCalls {
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
	request := expect.GET("/api/subscriptions/"+tc.username).WithHeader("Authorization", "Bearer "+jwtToken)
	response := request.Expect().Status(tc.status)

	// Assert response
	response.JSON().IsEqual(tc.responseBody)

	// Check if all expectations were met
	if err := poolMock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestSubscribeSuccessful(t *testing.T) {
	// Define test cases
	testCases := []testCaseStructureSubscription{
		{
			"Successful",
			"12345",
			"testUser",
			http.StatusOK,
			map[string]interface{}{
				"records": []map[string]interface{}{
					{
						"subscriptionId":   "dad19145-7a7d-4656-a2ae-5092cf543ec8",
						"subscriptionDate": "2024-01-30T20:17:09+01:00",
						"user": map[string]interface{}{
							"username":          "testo",
							"nickname":          "testi",
							"profilePictureURL": "/testUrl/",
						},
					},
				},
				"pagination": map[string]interface{}{
					"limit":   10,
					"offset":  0,
					"records": 1,
				},
			},
		},
	}

	// Iterate over test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTime, _ := time.Parse(time.RFC3339, "2024-01-30T20:17:09+01:00")
			runSubscriptionTestCase(t, tc, []MockDBCall{
				{
					Query:         "SELECT",
					Args:          []interface{}{tc.username},
					ReturnColumns: []string{"username"},
					ReturnValues:  []interface{}{tc.username},
				},
				{
					Query: `
						SELECT s.subscription_id, s.created_at, u.username, u.nickname, u.profile_picture_url
						FROM alpha_schema.subscriptions s
						INNER JOIN alpha_schema.users u ON s.subscriber_id = u.user_id
						WHERE s.subscribee_id = (SELECT user_id FROM alpha_schema.users WHERE username = $1)
						ORDER BY s.created_at DESC
					`,
					Args:          []interface{}{tc.username},
					ReturnColumns: []string{"subscription_id", "created_at", "username", "nickname", "profile_picture_url"},
					ReturnValues: []interface{}{
						tc.responseBody["records"].([]map[string]interface{})[0]["subscriptionId"],
						mockTime,
						tc.responseBody["records"].([]map[string]interface{})[0]["user"].(map[string]interface{})["username"],
						tc.responseBody["records"].([]map[string]interface{})[0]["user"].(map[string]interface{})["nickname"],
						tc.responseBody["records"].([]map[string]interface{})[0]["user"].(map[string]interface{})["profilePictureURL"],
					},
				},
				{
					Query:         `SELECT COUNT(*) FROM alpha_schema.subscriptions s WHERE s.subscribee_id = (SELECT user_id FROM alpha_schema.users WHERE username = $1)`,
					Args:          []interface{}{tc.username},
					ReturnColumns: []string{"count"},
					ReturnValues:  []interface{}{1},
				},
			})
		})
	}
}

func TestSubscribeBadRequest(t *testing.T) {
	// Define test cases
	testCases := []testCaseStructureSubscription{
		{
			"Bad Request",
			"12345",
			"", // Empty username
			http.StatusBadRequest,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The request body is invalid. Please check the request body and try again.",
					"code":    "ERR-001",
				},
			},
		},
	}

	// Iterate over each test case
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runSubscriptionTestCase(t, tc, []MockDBCall{})
		})
	}
}

func TestSubscribeUnauthorized(t *testing.T) {
	// Define test cases
	testCases := []testCaseStructureSubscription{
		{
			"Unauthorized",
			"12345",
			"testUser",
			http.StatusUnauthorized,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The request is unauthorized. Please login to your account.",
					"code":    "ERR-014",
				},
			},
		},
	}

	// Iterate over each test case
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for the database manager, JWT manager, and mail manager
			databaseMgrMock, jwtManagerMock, mailMgrMock := setupMocks(t)

			// Initialize the router with the mocks
			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManagerMock)

			// Create a new test server with the router
			server := httptest.NewServer(router)
			defer server.Close()

			// Get a mock of the database pool
			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

			// Create a new HTTP request and response expectation
			expect := httpexpect.Default(t, server.URL)
			// Create a GET request to the subscriptions endpoint with an invalid JWT token in the Authorization header
			request := expect.GET("/api/subscriptions/"+tc.username).WithHeader("Authorization", "Bearer "+"NonsenseToken")
			// Expect the HTTP status code and response body to match the test case
			response := request.Expect().Status(tc.status)
			response.JSON().IsEqual(tc.responseBody)

			// Check if all database expectations were met
			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestSubscribeNotFound(t *testing.T) {
	// Define test cases
	testCases := []testCaseStructureSubscription{
		{
			"User not found",
			"12345",
			"testUser",
			http.StatusNotFound,
			map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The user was not found. Please check the username and try again.",
					"code":    "ERR-004",
				},
			},
		},
	}

	// Iterate over each test case
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runSubscriptionTestCase(t, tc, []MockDBCall{
				{
					Query:         "SELECT",
					Args:          []interface{}{tc.username},
					ReturnColumns: []string{"username"},
					ReturnValues:  []interface{}{},
				},
			})
		})
	}
}
