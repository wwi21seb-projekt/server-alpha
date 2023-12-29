package routing

import (
	"github.com/gavv/httpexpect/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"server-alpha/internal/managers/mocks"
	"testing"
)

// define request payload for user registration
type RegisterUserRequest struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func setupMocks() (*mocks.MockDatabaseManager, *mocks.MockJwtManager, *mocks.MockMailManager) {
	poolMock, err := pgxmock.NewPool()
	if err != nil {
		panic(err)
	}

	databaseMgrMock := &mocks.MockDatabaseManager{}
	databaseMgrMock.On("GetPool").Return(poolMock)

	jwtManagerMock := &mocks.MockJwtManager{}
	jwtManagerMock.On("GenerateJWT", mock.AnythingOfType("jwt.Claims")).Return("testToken", nil)

	mailMgrMock := &mocks.MockMailManager{}
	mailMgrMock.On("SendActivationMail", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)

	return databaseMgrMock, jwtManagerMock, mailMgrMock
}

// TODO add tests for other routes
func TestUserRegistration(t *testing.T) {

	createUserRequest := func() RegisterUserRequest {
		return RegisterUserRequest{
			Username: "testUser",
			Nickname: "testNickname",
			Password: "test.Password123",
			Email:    "test@example.com",
		}
	}

	createUserRequestWithInvalidEmail := func() RegisterUserRequest {
		return RegisterUserRequest{
			Username: "testUser",
			Nickname: "testNickname",
			Password: "test.Password123",
			Email:    "test@example@.com",
		}
	}

	createUserRequestWithDuplicateUsername := func() RegisterUserRequest {
		return RegisterUserRequest{
			Username: "duplicateUser",
			Nickname: "duplicateNickname",
			Password: "duplicate.Password123",
			Email:    "duplicate@example.com",
		}
	}

	testCases := []struct {
		name         string
		user         RegisterUserRequest
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
