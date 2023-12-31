package routing

import (
	"crypto/ed25519"
	"encoding/pem"
	"github.com/gavv/httpexpect/v2"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"os"
	"server-alpha/internal/managers"
	"server-alpha/internal/managers/mocks"
	"strings"
	"testing"
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

func setupMocks() (*mocks.MockDatabaseManager, managers.JWTMgr, *mocks.MockMailManager) {
	poolMock, err := pgxmock.NewPool()
	if err != nil {
		panic(err)
	}

	databaseMgrMock := &mocks.MockDatabaseManager{}
	databaseMgrMock.On("GetPool").Return(poolMock)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("Failed to generate ed25519 keys: %v", err)
	}

	privateBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKey,
	}

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey,
	}

	privateKeyPem := string(pem.EncodeToMemory(privateBlock))
	publicKeyPem := string(pem.EncodeToMemory(publicBlock))

	privateKeyPem = strings.Replace(privateKeyPem, "-----BEGIN PRIVATE KEY-----\n", "", 1)
	privateKeyPem = strings.Replace(privateKeyPem, "\n-----END PRIVATE KEY-----", "", 1)
	privateKeyPem = strings.TrimSpace(privateKeyPem)

	publicKeyPem = strings.Replace(publicKeyPem, "-----BEGIN PUBLIC KEY-----\n", "", 1)
	publicKeyPem = strings.Replace(publicKeyPem, "\n-----END PUBLIC KEY-----", "", 1)
	publicKeyPem = strings.TrimSpace(publicKeyPem)

	_ = os.Setenv("JWT_PRIVATE_KEY", privateKeyPem)
	_ = os.Setenv("JWT_PUBLIC_KEY", publicKeyPem)

	jwtMgr, err := managers.NewJWTManager()
	if err != nil {
		panic(err)
	}

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

			databaseMgrMock, jwtManagerMock, mailMgrMock := setupMocks()

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
				poolMock.ExpectExec("INSERT").WithArgs(pgxmock.AnyArg(), tc.user.Username, tc.user.Nickname, tc.user.Email, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
				poolMock.ExpectExec("DELETE").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("DELETE", 0))
				poolMock.ExpectExec("INSERT").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
				poolMock.ExpectCommit()
			}

			// Assert that the response status code is 201 and the response body contains the expected values
			expect := httpexpect.Default(t, server.URL)
			request := expect.POST("/api/v1/users").WithJSON(tc.user)
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
			databaseMgrMock, jwtManagerMock, mailMgrMock := setupMocks()

			router := InitRouter(databaseMgrMock, mailMgrMock, jwtManagerMock)

			server := httptest.NewServer(router)
			defer server.Close()

			poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

			// Mock database calls
			poolMock.ExpectBegin()
			poolMock.ExpectQuery("SELECT activated_at").WithArgs(tc.user.Username).WillReturnRows(pgxmock.NewRows([]string{"activated_at"}).AddRow("2006-01-02 15:04:05.999999999Z"))
			poolMock.ExpectQuery("SELECT password, user_id").WithArgs(tc.user.Username).WillReturnRows(pgxmock.NewRows([]string{"password", "user_id"}).AddRow(tc.user.HashedPassword, tc.user.UserId))

			// Assert that the response status code is 200 and the response body contains the expected values
			expect := httpexpect.Default(t, server.URL)
			request := expect.POST("/api/v1/users/login").WithJSON(tc.user)
			request.Expect().Status(tc.status)

			if err := poolMock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}
