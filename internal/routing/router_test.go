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

// Create user registration request
func createUserRequest() RegisterUserRequest {
	return RegisterUserRequest{
		Username: "testUser",
		Nickname: "testNickname",
		Password: "test.Password123",
		Email:    "test@example.com",
	}
}

func TestUserRegistration(t *testing.T) {
	databaseMgrMock, jwtManagerMock, mailMgrMock := setupMocks()

	router := InitRouter(databaseMgrMock, mailMgrMock, jwtManagerMock)

	server := httptest.NewServer(router)
	defer server.Close()

	// Create user request
	user := createUserRequest()

	poolMock := databaseMgrMock.GetPool().(pgxmock.PgxPoolIface)

	// Mock database calls
	poolMock.ExpectBegin()
	poolMock.ExpectQuery("SELECT").WithArgs(user.Username, user.Email).WillReturnRows(pgxmock.NewRows([]string{"username", "email"}))
	poolMock.ExpectExec("INSERT").WithArgs(pgxmock.AnyArg(), user.Username, user.Nickname, user.Email, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	poolMock.ExpectExec("DELETE").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	poolMock.ExpectExec("INSERT").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	poolMock.ExpectCommit()

	// Assert that the response status code is 201 and the response body contains the expected values
	expect := httpexpect.Default(t, server.URL)
	request := expect.POST("/api/v1/users").WithJSON(user)
	response := request.Expect().Status(http.StatusCreated)
	response.JSON().Object().ContainsKey("username").HasValue("username", user.Username).ContainsKey("nickname").HasValue("nickname", user.Nickname).ContainsKey("email").HasValue("email", user.Email)
}
