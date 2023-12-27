package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
)

type UserHdl interface {
	RegisterUser(w http.ResponseWriter, r *http.Request)
	ActivateUser(w http.ResponseWriter, r *http.Request)
	ResendToken(w http.ResponseWriter, r *http.Request)
	LoginUser(w http.ResponseWriter, r *http.Request)
}

type UserHandler struct {
	DatabaseManager managers.DatabaseMgr
	JWTManager      managers.JWTMgr
	MailManager     managers.MailMgr
	Validator       *utils.Validator
}

func NewUserHandler(databaseManager *managers.DatabaseMgr, jwtManager *managers.JWTMgr, mailManager *managers.MailMgr) UserHdl {
	return &UserHandler{
		DatabaseManager: *databaseManager,
		JWTManager:      *jwtManager,
		MailManager:     *mailManager,
		Validator:       utils.GetValidator(),
	}
}

func (handler *UserHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel)

	// Decode the request body into the registration request struct
	registrationRequest := &schemas.RegistrationRequest{}
	if err := utils.DecodeRequestBody(w, r, registrationRequest); err != nil {
		return
	}

	// Validate the registration request struct using the validator
	if err := utils.ValidateStruct(w, registrationRequest); err != nil {
		return
	}

	// Check if the username or email is taken
	if err := checkUsernameEmailTaken(transactionCtx, w, tx, registrationRequest.Username, registrationRequest.Email); err != nil {
		return
	}

	// Check if the email exists
	if !handler.Validator.VerifyEmail(registrationRequest.Email) {
		utils.WriteAndLogError(w, schemas.EmailUnreachable, http.StatusBadRequest, errors.New("body invalid"))
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registrationRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.WriteAndLogError(w, schemas.InternalServerError, http.StatusInternalServerError, err)
		return
	}

	// Insert the user into the database
	userId := uuid.New()
	createdAt := time.Now()
	expiresAt := createdAt.Add(168 * time.Hour)

	queryString := "INSERT INTO users (user_id, username, nickname, email, password, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
	if _, err := tx.Exec(transactionCtx, queryString, userId, registrationRequest.Username, registrationRequest.Nickname, registrationRequest.Email, hashedPassword, createdAt, expiresAt); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Generate a token for the user
	if err := generateAndSendToken(w, handler, tx, transactionCtx, registrationRequest.Email, registrationRequest.Username, userId.String()); err != nil {
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	// Send success response
	w.WriteHeader(http.StatusCreated)
	userDto := &schemas.UserDTO{
		Username: registrationRequest.Username,
		Nickname: registrationRequest.Nickname,
		Email:    registrationRequest.Email,
	}

	if err := json.NewEncoder(w).Encode(userDto); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (handler *UserHandler) ActivateUser(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel)

	// Decode the request body into the activation request struct
	activationRequest := &schemas.ActivationRequest{}
	if err := utils.DecodeRequestBody(w, r, activationRequest); err != nil {
		return
	}

	// Get username from path
	username := chi.URLParam(r, "username")

	// Validate the activation request struct using the validator
	if err := utils.ValidateStruct(w, activationRequest); err != nil {
		return
	}

	// Get the user ID
	_, userID, errorOccurred := retrieveUserIdAndEmail(transactionCtx, w, tx, username)
	if errorOccurred {
		return
	}

	// Check if the user is activated
	if _, activated, err := checkUserExistenceAndActivation(transactionCtx, w, tx, username); err != nil {

	} else if activated {
		utils.WriteAndLogError(w, schemas.UserAlreadyActivated, http.StatusAlreadyReported, errors.New("already activated"))
		return
	}

	// Check if the token is valid
	if err := checkTokenValidity(transactionCtx, w, tx, activationRequest.Token, username); err != nil {
		return
	}

	// Activate the user
	queryString := "UPDATE users SET activated_at = $1 WHERE user_id = $2"
	if _, err := tx.Exec(transactionCtx, queryString, time.Now(), userID); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Delete the token
	queryString = "DELETE FROM user_token WHERE token = $1"
	if _, err := tx.Exec(transactionCtx, queryString, activationRequest.Token); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (handler *UserHandler) ResendToken(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel)

	// Get username from path
	username := chi.URLParam(r, "username")

	email, userId, errorOccurred := retrieveUserIdAndEmail(transactionCtx, w, tx, username)
	if errorOccurred {
		return
	}

	// Check if the user is activated
	if _, activated, err := checkUserExistenceAndActivation(transactionCtx, w, tx, username); err != nil {
		return
	} else if activated {
		utils.WriteAndLogError(w, schemas.UserAlreadyActivated, http.StatusAlreadyReported, errors.New("already activated"))
		return
	}

	// Generate a new token and send it to the user
	if err := generateAndSendToken(w, handler, tx, transactionCtx, email, username, userId.String()); err != nil {
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (handler *UserHandler) LoginUser(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel)

	// Decode the request body into the login request struct
	loginRequest := &schemas.LoginRequest{}
	if err := utils.DecodeRequestBody(w, r, loginRequest); err != nil {
		return
	}

	// Validate the registration request struct using the validator
	if err := utils.ValidateStruct(w, loginRequest); err != nil {
		return
	}

	// Check if user exists and if yes, if he is activated
	exists, activated, err := checkUserExistenceAndActivation(transactionCtx, w, tx, loginRequest.Username)
	if err != nil {
		return
	}

	if !exists {
		utils.WriteAndLogError(w, schemas.InvalidCredentials, 404, errors.New("username does not exist"))
		return
	}

	if !activated {
		utils.WriteAndLogError(w, schemas.UserNotActivated, 403, errors.New("user not activated"))
		return
	}

	// Check if password matches
	queryString := "SELECT password FROM users WHERE username = $1"
	rows, err := tx.Query(transactionCtx, queryString, loginRequest.Username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	var password string
	rows.Next() // We already asserted existence earlier, so we can assume that the row exists

	if err := rows.Scan(&password); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(loginRequest.Password)); err != nil {
		utils.WriteAndLogError(w, schemas.InvalidCredentials, http.StatusInternalServerError, err)
		return
	}

	// Generate a token for the user
	claims := handler.JWTManager.GenerateClaims(loginRequest.Username)
	token, err := handler.JWTManager.GenerateJWT(claims)

	tokenDto := &schemas.TokenDTO{
		Token: token,
	}

	if err := json.NewEncoder(w).Encode(tokenDto); err != nil {
		utils.WriteAndLogError(w, schemas.InternalServerError, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(200)
}

func retrieveUserIdAndEmail(transactionCtx context.Context, w http.ResponseWriter, tx pgx.Tx, username string) (string, uuid.UUID, bool) {
	// Get the user ID
	queryString := "SELECT email, user_id FROM users WHERE username = $1"
	rows, err := tx.Query(transactionCtx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return "", uuid.UUID{}, true
	}
	defer rows.Close()

	var email string
	var userID uuid.UUID
	if rows.Next() {
		if err := rows.Scan(&email, &userID); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return "", uuid.UUID{}, true
		}
	} else {
		utils.WriteAndLogError(w, schemas.UserNotFound, http.StatusNotFound, errors.New("user not found"))
		return "", uuid.UUID{}, true
	}

	return email, userID, false
}

func checkUsernameEmailTaken(ctx context.Context, w http.ResponseWriter, tx pgx.Tx, username, email string) error {
	queryString := "SELECT username, email FROM users WHERE username = $1 OR email = $2"
	rows, err := tx.Query(ctx, queryString, username, email)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}
	defer rows.Close()

	if rows.Next() {
		var foundUsername string
		var foundEmail string

		if err := rows.Scan(&foundUsername, &foundEmail); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return err
		}

		customErr := &schemas.CustomError{}
		if foundUsername == username {
			customErr = schemas.UsernameTaken
		} else {
			customErr = schemas.EmailTaken
		}

		err = errors.New("username or email taken")
		utils.WriteAndLogError(w, customErr, http.StatusConflict, err)
		return err
	}

	return nil
}

func checkTokenValidity(ctx context.Context, w http.ResponseWriter, tx pgx.Tx, token, username string) error {
	queryString := "SELECT expires_at FROM user_token WHERE token = $1 AND user_id = (SELECT user_id FROM users WHERE username = $2)"
	rows, err := tx.Query(ctx, queryString, token, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}
	defer rows.Close()

	if !rows.Next() {
		utils.WriteAndLogError(w, schemas.InvalidToken, http.StatusUnauthorized, errors.New("invalid token"))
		return errors.New("invalid token")
	}

	var expiresAt pgtype.Timestamptz
	if err := rows.Scan(&expiresAt); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	if time.Now().After(expiresAt.Time) {
		utils.WriteAndLogError(w, schemas.ActivationTokenExpired, http.StatusUnauthorized, errors.New("token expired"))
		return errors.New("token expired")
	}

	return nil
}

func checkUserExistenceAndActivation(ctx context.Context, w http.ResponseWriter, tx pgx.Tx, username string) (bool, bool, error) {
	queryString := "SELECT activated_at FROM users WHERE username = $1"
	rows, err := tx.Query(ctx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return false, false, err
	}
	defer rows.Close()

	var activatedAt pgtype.Timestamptz
	if rows.Next() {
		if err := rows.Scan(&activatedAt); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return false, false, err
		}
	} else {
		return false, false, nil
	}

	return true, !activatedAt.Time.IsZero() && activatedAt.Valid, nil
}

func generateAndSendToken(w http.ResponseWriter, handler *UserHandler, tx pgx.Tx, ctx context.Context, email, username, userId string) error {
	// Generate a new token and send it to the user
	token := generateToken()
	tokenID := uuid.New()
	tokenExpiresAt := time.Now().Add(2 * time.Hour)

	// Delete the old token if it exists
	queryString := "DELETE FROM user_token WHERE user_id = $1"
	if _, err := tx.Exec(ctx, queryString, userId); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	queryString = "INSERT INTO user_token (token_id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)"
	if _, err := tx.Exec(ctx, queryString, tokenID, userId, token, tokenExpiresAt); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	// Send the token to the user
	if err := handler.MailManager.SendActivationMail(email, username, token, "UI-Service"); err != nil {
		utils.WriteAndLogError(w, schemas.EmailNotSent, http.StatusInternalServerError, err)
		return err
	}

	return nil
}

func generateToken() string {
	rand.NewSource(time.Now().UnixNano())

	// Generate a random 6-digit number
	return strconv.Itoa(rand.Intn(900000) + 100000)
}
