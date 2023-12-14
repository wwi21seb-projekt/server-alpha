package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"log"
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
}

type UserHandler struct {
	DatabaseManager managers.DatabaseMgr
	MailManager     managers.MailMgr
	Validator       *utils.Validator
}

func (handler *UserHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	defer utils.RollbackTransaction(w, tx, transactionCtx)
	defer cancel()

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
	if err := checkUsernameEmailTaken(w, tx, transactionCtx, registrationRequest.Username, registrationRequest.Email); err != nil {
		return
	}

	// Check if the email exists
	if !handler.Validator.VerifyEmail(registrationRequest.Email) {
		utils.WriteAndLogError(w, schemas.EmailUnreachable, http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registrationRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.WriteAndLogError(w, schemas.InternalServerError, http.StatusInternalServerError)
		return
	}

	// Insert the user into the database
	userId := uuid.New()
	createdAt := time.Now()
	expiresAt := createdAt.Add(168 * time.Hour)

	queryString := "INSERT INTO users (user_id, username, nickname, email, password, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
	if _, err := tx.Exec(transactionCtx, queryString, userId, registrationRequest.Username, registrationRequest.Nickname, registrationRequest.Email, hashedPassword, createdAt, expiresAt); err != nil {
		log.Println("err 1")
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return
	}
	log.Println("I'm here 3")

	// Generate a token for the user
	if err := generateAndSendToken(w, handler, tx, transactionCtx, registrationRequest.Email, registrationRequest.Username, userId.String()); err != nil {
		return
	}
	log.Println("I'm here 4")

	// Commit the transaction
	utils.CommitTransaction(w, tx, transactionCtx)

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
	defer utils.RollbackTransaction(w, tx, transactionCtx)
	defer cancel()

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
	queryString := "SELECT user_id FROM users WHERE username = $1"
	rows, err := tx.Query(transactionCtx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return
	}

	var userID uuid.UUID
	if rows.Next() {
		if err := rows.Scan(&userID); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
			return
		}
	} else {
		utils.WriteAndLogError(w, schemas.UserNotFound, http.StatusNotFound)
		return
	}

	// Check if the token is valid
	if err := checkTokenValidity(w, tx, transactionCtx, activationRequest.Token, username); err != nil {
		return
	}

	// Activate the user
	queryString = "UPDATE users SET activated_at = $1 WHERE user_id = $2"
	if _, err := tx.Exec(transactionCtx, queryString, time.Now(), userID); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return
	}

	// Delete the token
	queryString = "DELETE FROM user_token WHERE token = $1"
	if _, err := tx.Exec(transactionCtx, queryString, activationRequest.Token); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return
	}

	utils.CommitTransaction(w, tx, transactionCtx)
	w.WriteHeader(http.StatusNoContent)
}

func (handler *UserHandler) ResendToken(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	defer utils.RollbackTransaction(w, tx, transactionCtx)
	defer cancel()

	// Get username from path
	username := chi.URLParam(r, "username")

	// Check if the user exists
	if err := checkUserExistence(w, tx, transactionCtx, username); err != nil {
		return
	}

	// Check if the user is activated
	if err, activated := checkUserActivation(w, tx, transactionCtx, username); err != nil {
		return
	} else if activated {
		utils.WriteAndLogError(w, schemas.UserAlreadyActivated, http.StatusBadRequest)
		return
	}

	// Get the user's email
	queryString := "SELECT email, user_id FROM users WHERE username = $1"
	rows, err := tx.Query(transactionCtx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return
	}

	var email string
	var userId string
	if rows.Next() {
		if err := rows.Scan(&email, &userId); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
			return
		}
	}

	// Generate a new token and send it to the user
	if err := generateAndSendToken(w, handler, tx, transactionCtx, email, username, userId); err != nil {
		return
	}

	// Commit the transaction
	utils.CommitTransaction(w, tx, transactionCtx)
	w.WriteHeader(http.StatusNoContent)
}

func checkUsernameEmailTaken(w http.ResponseWriter, tx pgx.Tx, ctx context.Context, username, email string) error {
	queryString := "SELECT username, email FROM users WHERE username = $1 OR email = $2"
	rows, err := tx.Query(ctx, queryString, username, email)
	log.Println("I'm here")
	if err != nil {
		log.Println("error is here")
		log.Println(err)
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return err
	}
	defer rows.Close()

	if rows.Next() {
		var foundUsername string
		var foundEmail string

		if err := rows.Scan(&foundUsername, &foundEmail); err != nil {
			log.Println("?!?!?")
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
			return err
		}
		log.Println("I'm here 2")

		customErr := &schemas.CustomError{}
		if foundUsername == username {
			customErr = schemas.UsernameTaken
		} else {
			customErr = schemas.EmailTaken
		}

		utils.WriteAndLogError(w, customErr, http.StatusConflict)
		return errors.New("username or email taken")
	}

	return nil
}

func checkTokenValidity(w http.ResponseWriter, tx pgx.Tx, ctx context.Context, token, username string) error {
	queryString := "SELECT user_id FROM user_token WHERE token = $1 AND user_id = (SELECT user_id FROM users WHERE username = $2)"
	rows, err := tx.Query(ctx, queryString, token, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return err
	}
	defer rows.Close()

	if !rows.Next() {
		utils.WriteAndLogError(w, schemas.InvalidToken, http.StatusUnauthorized)
		return errors.New("invalid token")
	}

	return nil
}

func checkUserExistence(w http.ResponseWriter, tx pgx.Tx, ctx context.Context, username string) error {
	queryString := "SELECT user_id FROM users WHERE username = $1"
	rows, err := tx.Query(ctx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return err
	}
	defer rows.Close()

	if !rows.Next() {
		utils.WriteAndLogError(w, schemas.UserNotFound, http.StatusNotFound)
		return errors.New("user not found")
	}

	return nil
}

func checkUserActivation(w http.ResponseWriter, tx pgx.Tx, ctx context.Context, username string) (error, bool) {
	queryString := "SELECT activated_at FROM users WHERE username = $1"
	rows, err := tx.Query(ctx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return err, false
	}
	defer rows.Close()

	var activatedAt *time.Time
	if err := rows.Scan(&activatedAt); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return err, false
	}

	return nil, activatedAt != nil
}

func generateAndSendToken(w http.ResponseWriter, handler *UserHandler, tx pgx.Tx, ctx context.Context, email, username, userId string) error {
	// Generate a new token and send it to the user
	token := generateToken()
	tokenID := uuid.New()
	tokenExpiresAt := time.Now().Add(2 * time.Hour)

	// Delete the old token if it exists
	queryString := "DELETE FROM user_token WHERE user_id = $1"
	if _, err := tx.Exec(ctx, queryString, userId); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return err
	}

	queryString = "INSERT INTO user_token (token_id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)"
	if _, err := tx.Exec(ctx, queryString, tokenID, userId, token, tokenExpiresAt); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError)
		return err
	}

	// Send the token to the user
	if err := handler.MailManager.SendActivationMail(email, username, token, "UI-Service"); err != nil {
		utils.WriteAndLogError(w, schemas.EmailNotSent, http.StatusInternalServerError)
		return err
	}

	return nil
}

func generateToken() string {
	rand.NewSource(time.Now().UnixNano())

	// Generate a random 6-digit number
	return strconv.Itoa(rand.Intn(900000) + 100000)
}

func NewUserHandler(databaseManager *managers.DatabaseMgr, mailManager *managers.MailMgr) UserHdl {
	return &UserHandler{
		DatabaseManager: *databaseManager,
		MailManager:     *mailManager,
		Validator:       utils.GetValidator(),
	}
}
