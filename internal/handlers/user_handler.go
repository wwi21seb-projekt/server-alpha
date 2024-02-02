package handlers

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	log "github.com/sirupsen/logrus"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
)

// UserHdl defines the interface for handling user-related HTTP requests.
type UserHdl interface {
	RegisterUser(w http.ResponseWriter, r *http.Request)
	ActivateUser(w http.ResponseWriter, r *http.Request)
	ResendToken(w http.ResponseWriter, r *http.Request)
	LoginUser(w http.ResponseWriter, r *http.Request)
	HandleGetUserRequest(w http.ResponseWriter, r *http.Request)
	SearchUsers(w http.ResponseWriter, r *http.Request)
	ChangeTrivialInformation(w http.ResponseWriter, r *http.Request)
	ChangePassword(w http.ResponseWriter, r *http.Request)
	RefreshToken(w http.ResponseWriter, r *http.Request)
	RetrieveUserPosts(w http.ResponseWriter, r *http.Request)
}

// UserHandler provides methods to handle user-related HTTP requests.
type UserHandler struct {
	DatabaseManager managers.DatabaseMgr
	JWTManager      managers.JWTMgr
	MailManager     managers.MailMgr
	Validator       *utils.Validator
}

// NewUserHandler returns a new UserHandler with the provided managers and validator.
func NewUserHandler(databaseManager *managers.DatabaseMgr, jwtManager *managers.JWTMgr, mailManager *managers.MailMgr) UserHdl {
	return &UserHandler{
		DatabaseManager: *databaseManager,
		JWTManager:      *jwtManager,
		MailManager:     *mailManager,
		Validator:       utils.GetValidator(),
	}
}

var errInvalidToken = errors.New("invalid token")

// RegisterUser handles the registration of a new user by validating the request, checking for username or email availability,
// hashing the password, inserting the user into the database, generating and sending an activation token, and committing the transaction.
func (handler *UserHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Decode the request body into the registration request struct
	registrationRequest := &schemas.RegistrationRequest{}
	if err = utils.DecodeRequestBody(transactionCtx, w, r, registrationRequest); err != nil {
		return
	}

	// Validate the registration request struct using the validator
	if err = utils.ValidateStruct(transactionCtx, w, registrationRequest); err != nil {
		return
	}

	// Check if the username or email is taken
	if err = checkUsernameEmailTaken(transactionCtx, w, tx, registrationRequest.Username, registrationRequest.Email); err != nil {
		return
	}

	// Check if the email exists
	/* CURRENTLY NOT WORKING
	if !handler.Validator.VerifyEmail(registrationRequest.Email) {
		utils.WriteAndLogError(w, schemas.EmailUnreachable, http.StatusBadRequest, errors.New("body invalid"))
		return
	}
	*/

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registrationRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.InternalServerError, http.StatusInternalServerError, err)
		return
	}

	// Insert the user into the database
	userId := uuid.New()
	createdAt := time.Now()
	expiresAt := createdAt.Add(168 * time.Hour)

	queryString := "INSERT INTO alpha_schema.users (user_id, username, nickname, email, password, created_at, expires_at, status, profile_picture_url) VALUES ($1, $2, $3, $4, $5, $6, $7,$8,$9)"
	if _, err = tx.Exec(transactionCtx, queryString, userId, registrationRequest.Username, registrationRequest.Nickname, registrationRequest.Email, hashedPassword, createdAt, expiresAt, "", ""); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Generate a token for the user
	if err = generateAndSendToken(transactionCtx, w, handler, tx, registrationRequest.Email, registrationRequest.Username, userId.String()); err != nil {
		return
	}

	// Commit the transaction
	if err = utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	userDto := &schemas.UserDTO{
		Username: registrationRequest.Username,
		Nickname: registrationRequest.Nickname,
		Email:    registrationRequest.Email,
	}

	// Send success response
	utils.WriteAndLogResponse(transactionCtx, w, userDto, http.StatusCreated)
}

// ActivateUser handles user activation by validating the request, checking user existence and activation status,
// validating the activation token, updating the user's activation status in the database, deleting the token,
// generating a new token pair, and committing the transaction.
func (handler *UserHandler) ActivateUser(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Decode the request body into the activation request struct
	activationRequest := &schemas.ActivationRequest{}
	if err := utils.DecodeRequestBody(transactionCtx, w, r, activationRequest); err != nil {
		return
	}

	// Get username from path
	username := chi.URLParam(r, utils.UsernameKey)

	// Validate the activation request struct using the validator
	if err := utils.ValidateStruct(transactionCtx, w, activationRequest); err != nil {
		return
	}

	// Get the user ID
	_, userID, errorOccurred := retrieveUserIdAndEmail(transactionCtx, w, tx, username)
	if errorOccurred {
		return
	}

	// Check if the user is activated
	if _, activated, err := checkUserExistenceAndActivation(transactionCtx, w, tx, username); err != nil {
		return
	} else if activated {
		utils.WriteAndLogError(transactionCtx, w, schemas.UserAlreadyActivated, http.StatusAlreadyReported,
			errors.New("already activated"))
		return
	}

	// Check if the token is valid
	if err := checkTokenValidity(transactionCtx, w, tx, activationRequest.Token, username); err != nil {
		return
	}

	// Activate the user
	queryString := "UPDATE alpha_schema.users SET activated_at = $1 WHERE user_id = $2"
	if _, err := tx.Exec(transactionCtx, queryString, time.Now(), userID); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Delete the token
	queryString = "DELETE FROM alpha_schema.activation_tokens WHERE token = $1"
	if _, err := tx.Exec(transactionCtx, queryString, activationRequest.Token); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Generate token pair
	tokenDto, err := generateTokenPair(handler, userID.String(), username)
	if err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.InternalServerError, http.StatusInternalServerError, err)
		return
	}

	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	utils.WriteAndLogResponse(transactionCtx, w, tokenDto, http.StatusOK)
}

// ResendToken handles resending the activation token by validating the request, checking user existence and activation status,
// generating and sending a new token, and committing the transaction.
func (handler *UserHandler) ResendToken(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Get username from path
	username := chi.URLParam(r, utils.UsernameKey)

	email, userId, errorOccurred := retrieveUserIdAndEmail(transactionCtx, w, tx, username)
	if errorOccurred {
		return
	}

	// Check if the user is activated
	if _, activated, err := checkUserExistenceAndActivation(transactionCtx, w, tx, username); err != nil {
		return
	} else if activated {
		utils.WriteAndLogError(transactionCtx, w, schemas.UserAlreadyActivated, http.StatusAlreadyReported,
			errors.New("already activated"))
		return
	}

	// Generate a new token and send it to the user
	if err := generateAndSendToken(transactionCtx, w, handler, tx, email, username, userId.String()); err != nil {
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ChangeTrivialInformation handles changes to trivial information of the user like nickname and status by
// validating the request, updating the information in the database, and committing the transaction.
func (handler *UserHandler) ChangeTrivialInformation(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Decode the request body into the nickname change request struct
	changeTrivialInformationRequest := &schemas.ChangeTrivialInformationRequest{}
	if err := utils.DecodeRequestBody(transactionCtx, w, r, changeTrivialInformationRequest); err != nil {
		return
	}

	// Validate the nickname change request struct using the validator
	if err := utils.ValidateStruct(transactionCtx, w, changeTrivialInformationRequest); err != nil {
		return
	}

	// Get the user ID from the JWT token
	claims, ok := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)
	if !ok {
		utils.WriteAndLogError(transactionCtx, w, schemas.Unauthorized, http.StatusUnauthorized,
			errors.New("unauthorized"))
		return
	}
	userId := claims["sub"].(string)

	// Change the user's nickname and status
	queryString := "UPDATE alpha_schema.users SET nickname = $1, status = $2 WHERE user_id = $3"
	if _, err := tx.Exec(transactionCtx, queryString, changeTrivialInformationRequest.NewNickname, changeTrivialInformationRequest.Status, userId); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Retrieve the updated user
	UserNicknameAndStatusDTO := &schemas.UserNicknameAndStatusDTO{}
	UserNicknameAndStatusDTO.Nickname = changeTrivialInformationRequest.NewNickname
	UserNicknameAndStatusDTO.Status = changeTrivialInformationRequest.Status

	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	// Send the updated user in the response
	utils.WriteAndLogResponse(transactionCtx, w, UserNicknameAndStatusDTO, http.StatusOK)
}

// ChangePassword handles changing the password of the user by validating the request, checking the old password,
// hashing the new password, updating the password in the database, and committing the transaction.
func (handler *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Decode the request body into the password change request struct
	passwordChangeRequest := &schemas.ChangePasswordRequest{}
	if err = utils.DecodeRequestBody(transactionCtx, w, r, passwordChangeRequest); err != nil {
		return
	}

	// Validate the password change request struct using the validator
	if err = utils.ValidateStruct(transactionCtx, w, passwordChangeRequest); err != nil {
		return
	}

	// Get the user ID from the JWT token
	claims, ok := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)
	if !ok {
		utils.WriteAndLogError(transactionCtx, w, schemas.Unauthorized, http.StatusUnauthorized,
			errors.New("unauthorized"))
		return
	}
	username := claims["username"].(string)
	userId := claims["sub"].(string)

	// Check if old password is correct
	if err = checkPassword(transactionCtx, w, tx, username, passwordChangeRequest.OldPassword); err != nil {
		return
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwordChangeRequest.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.InternalServerError, http.StatusInternalServerError, err)
		return
	}

	// Update the user's password in the database
	queryString := "UPDATE alpha_schema.users SET password = $1 WHERE user_id = $2"
	if _, err = tx.Exec(transactionCtx, queryString, hashedPassword, userId); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Commit the transaction
	if err = utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	// Send success response
	w.WriteHeader(http.StatusNoContent)
}

// LoginUser handles user login by validating the request, checking user existence, activation status, and password correctness,
// generating a new token pair, and committing the transaction.
func (handler *UserHandler) LoginUser(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Decode the request body into the login request struct
	loginRequest := &schemas.LoginRequest{}
	if err := utils.DecodeRequestBody(transactionCtx, w, r, loginRequest); err != nil {
		return
	}

	// Validate the registration request struct using the validator
	if err := utils.ValidateStruct(transactionCtx, w, loginRequest); err != nil {
		return
	}

	// Check if user exists and if yes, if he is activated
	exists, activated, err := checkUserExistenceAndActivation(transactionCtx, w, tx, loginRequest.Username)
	if err != nil {
		return
	}

	if !exists {
		utils.WriteAndLogError(transactionCtx, w, schemas.InvalidCredentials, 404,
			errors.New("username does not exist"))
		return
	}

	if !activated {
		utils.WriteAndLogError(transactionCtx, w, schemas.UserNotActivated, 403,
			errors.New("user not activated"))
		return
	}

	// Check if password is correct
	if err = checkPassword(transactionCtx, w, tx, loginRequest.Username, loginRequest.Password); err != nil {
		return
	}

	// Get the user ID
	_, userId, errorOccurred := retrieveUserIdAndEmail(transactionCtx, w, tx, loginRequest.Username)
	if errorOccurred {
		return
	}

	// Generate token pair
	tokenDto, err := generateTokenPair(handler, userId.String(), loginRequest.Username)
	if err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.InternalServerError, http.StatusInternalServerError, err)
		return

	}

	// Commit the transaction
	if err = utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	// Send success response
	utils.WriteAndLogResponse(transactionCtx, w, tokenDto, http.StatusOK)
}

// HandleGetUserRequest handles fetching a user profile based on the username in the path parameter
// and sends the profile data along with the number of posts, followers, and followings.
func (handler *UserHandler) HandleGetUserRequest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithDeadline(r.Context(), time.Now().Add(10*time.Second))
	defer func() {
		if err := ctx.Err(); err != nil {
			log.Debug("Context error: ", err)
		}
		cancel()
		log.Debug("Context canceled")
	}()

	user := schemas.UserProfileDTO{}
	var userId uuid.UUID

	// Get username from path
	username := chi.URLParam(r, utils.UsernameKey)

	queryString := "SELECT user_id, username, nickname, status, profile_picture_url FROM alpha_schema.users WHERE username = $1"

	row := handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, username)
	if err := row.Scan(&userId, &user.Username, &user.Nickname, &user.Status, &user.ProfilePicture); err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the number of posts the user has
	queryString = "SELECT COUNT(*) FROM alpha_schema.posts WHERE author_id = $1"
	row = handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, userId)
	if err := row.Scan(&user.Posts); err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the number of followers the user has
	queryString = "SELECT COUNT(*) FROM alpha_schema.subscriptions WHERE subscribee_id = $1"
	row = handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, userId)
	if err := row.Scan(&user.Follower); err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the number of users the user is following
	queryString = "SELECT COUNT(*) FROM alpha_schema.subscriptions WHERE subscriber_id = $1"
	row = handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, userId)
	if err := row.Scan(&user.Following); err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the user ID from the JWT token
	claims := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)
	jwtUserId := claims["sub"].(string)

	// Get the subscription ID
	queryString = "SELECT subscription_id FROM alpha_schema.subscriptions WHERE subscriber_id = $1 AND subscribee_id = $2"
	row = handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, jwtUserId, userId)
	if err := row.Scan(&user.SubscriptionId); err != nil {
		user.SubscriptionId = nil
	}

	// Send success response
	utils.WriteAndLogResponse(ctx, w, user, http.StatusOK)
}

// SearchUsers handles searching for users based on the search query in the request parameters and sends a paginated list of users.
func (handler *UserHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithDeadline(r.Context(), time.Now().Add(10*time.Second))
	defer func() {
		if err := ctx.Err(); err != nil {
			log.Debug("Context error: ", err)
		}
		cancel()
		log.Debug("Context canceled")
	}()

	// Get the search query from the query parameters
	searchQuery := r.URL.Query().Get(utils.UsernameParamKey)

	offset, limit, err := utils.ParsePaginationParams(r)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.BadRequest, http.StatusBadRequest, err)
		return
	}

	// Get the users that match the search query
	queryString := "SELECT username, nickname, profile_picture_url, levenshtein(username, $1) as ld FROM alpha_schema.users WHERE levenshtein(username, $1) <= 5 ORDER BY ld"
	rows, err := handler.DatabaseManager.GetPool().Query(ctx, queryString, searchQuery)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	// Create a list of users
	users := make([]schemas.AuthorDTO, 0)
	var ld int
	for rows.Next() {
		user := schemas.AuthorDTO{}
		if err := rows.Scan(&user.Username, &user.Nickname, &user.ProfilePictureURL, &ld); err != nil {
			utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}
		users = append(users, user)
	}

	utils.SendPaginatedResponse(ctx, w, users, offset, limit, len(users))
}

// RefreshToken handles refreshing the user's token by validating the request, extracting the user ID and username from the refresh token,
// generating a new token pair, and sending it in the response.
func (handler *UserHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get the refresh token from the request body
	refreshTokenRequest := &schemas.RefreshTokenRequest{}
	if err := utils.DecodeRequestBody(ctx, w, r, refreshTokenRequest); err != nil {
		return
	}

	// Validate the refresh token request struct using the validator
	if err := utils.ValidateStruct(ctx, w, refreshTokenRequest); err != nil {
		return
	}

	// Get the user ID and username from the refresh token
	refreshTokenClaims, err := handler.JWTManager.ValidateJWT(refreshTokenRequest.RefreshToken)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.InvalidToken, http.StatusUnauthorized, err)
		return
	}

	refreshClaims := refreshTokenClaims.(jwt.MapClaims)
	userId := refreshClaims["sub"].(string)
	username := refreshClaims["username"].(string)
	isRefreshToken := refreshClaims["refresh"].(string)

	if isRefreshToken != "true" {
		utils.WriteAndLogError(ctx, w, schemas.Unauthorized, http.StatusUnauthorized, errInvalidToken)
		return
	}

	// Generate token pair
	tokenDto, err := generateTokenPair(handler, userId, username)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.InternalServerError, http.StatusInternalServerError, err)
		return
	}

	// Send success response
	utils.WriteAndLogResponse(ctx, w, tokenDto, http.StatusOK)
}

// RetrieveUserPosts handles fetching posts of a user based on the username in the path parameter and sends a paginated list of posts.
func retrieveUserIdAndEmail(transactionCtx context.Context, w http.ResponseWriter, tx pgx.Tx, username string) (string, uuid.UUID, bool) {
	// Get the user ID
	queryString := "SELECT email, user_id FROM alpha_schema.users WHERE username = $1"
	rows, err := tx.Query(transactionCtx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return "", uuid.UUID{}, true
	}
	defer rows.Close()

	var email string
	var userID uuid.UUID
	if rows.Next() {
		if err := rows.Scan(&email, &userID); err != nil {
			utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return "", uuid.UUID{}, true
		}
	} else {
		utils.WriteAndLogError(transactionCtx, w, schemas.UserNotFound, http.StatusNotFound,
			errors.New("user not found"))
		return "", uuid.UUID{}, true
	}

	return email, userID, false
}

// checkUsernameEmailTaken checks if the username or email is taken.
func checkUsernameEmailTaken(ctx context.Context, w http.ResponseWriter, tx pgx.Tx, username, email string) error {
	queryString := "SELECT username, email FROM alpha_schema.users WHERE username = $1 OR email = $2"
	rows, err := tx.Query(ctx, queryString, username, email)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}
	defer rows.Close()

	if rows.Next() {
		var foundUsername string
		var foundEmail string

		if err := rows.Scan(&foundUsername, &foundEmail); err != nil {
			utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return err
		}

		customErr := &schemas.CustomError{}
		if foundUsername == username {
			customErr = schemas.UsernameTaken
		} else {
			customErr = schemas.EmailTaken
		}

		err = errors.New("username or email taken")
		utils.WriteAndLogError(ctx, w, customErr, http.StatusConflict, err)
		return err
	}

	return nil
}

// checkTokenValidity checks if the token for the given user and token value combination is valid.
func checkTokenValidity(ctx context.Context, w http.ResponseWriter, tx pgx.Tx, token, username string) error {
	queryString := "SELECT expires_at FROM alpha_schema.activation_tokens WHERE token = $1 AND user_id = (SELECT user_id FROM alpha_schema.users WHERE username = $2)"
	rows, err := tx.Query(ctx, queryString, token, username)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}
	defer rows.Close()

	if !rows.Next() {
		utils.WriteAndLogError(ctx, w, schemas.InvalidToken, http.StatusUnauthorized, errInvalidToken)
		return errInvalidToken
	}

	var expiresAt pgtype.Timestamptz
	if err := rows.Scan(&expiresAt); err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	if time.Now().After(expiresAt.Time) {
		utils.WriteAndLogError(ctx, w, schemas.ActivationTokenExpired, http.StatusUnauthorized,
			errors.New("token expired"))
		return errors.New("token expired")
	}

	return nil
}

// checkUserExistenceAndActivation checks if the user exists and if yes, returns separate values for existence and activation.
func checkUserExistenceAndActivation(ctx context.Context, w http.ResponseWriter, tx pgx.Tx, username string) (bool, bool, error) {
	queryString := "SELECT activated_at FROM alpha_schema.users WHERE username = $1"
	rows, err := tx.Query(ctx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return false, false, err
	}
	defer rows.Close()

	var activatedAt pgtype.Timestamptz
	if rows.Next() {
		if err := rows.Scan(&activatedAt); err != nil {
			utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return false, false, err
		}
	} else {
		return false, false, nil
	}

	return true, !activatedAt.Time.IsZero() && activatedAt.Valid, nil
}

// generateAndSendToken generates a new token and sends it to the user's email.
func generateAndSendToken(ctx context.Context, w http.ResponseWriter, handler *UserHandler, tx pgx.Tx, email, username, userId string) error {
	// Generate a new token and send it to the user
	token := generateToken()
	tokenID := uuid.New()
	tokenExpiresAt := time.Now().Add(2 * time.Hour)

	// Delete the old token if it exists
	queryString := "DELETE FROM alpha_schema.activation_tokens WHERE user_id = $1"
	if _, err := tx.Exec(ctx, queryString, userId); err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	queryString = "INSERT INTO alpha_schema.activation_tokens (token_id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)"
	if _, err := tx.Exec(ctx, queryString, tokenID, userId, token, tokenExpiresAt); err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	// Send the token to the user
	if err := handler.MailManager.SendActivationMail(email, username, token, "UI-Service"); err != nil {
		utils.WriteAndLogError(ctx, w, schemas.EmailNotSent, http.StatusInternalServerError, err)
		return err
	}

	return nil
}

// generateToken generates a new token for the user activation.
func generateToken() string {
	rand.NewSource(time.Now().UnixNano())

	// Generate a random 6-digit number
	return strconv.Itoa(rand.Intn(900000) + 100000)
}

// checkPassword checks if the given password is correct for the given user.
func checkPassword(transactionCtx context.Context, w http.ResponseWriter, tx pgx.Tx, username, givenPassword string) error {
	queryString := "SELECT password, user_id FROM alpha_schema.users WHERE username = $1"
	rows, err := tx.Query(transactionCtx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}
	defer rows.Close()

	var password string
	var userId uuid.UUID
	rows.Next() // We already asserted existence earlier, so we can assume that the row exists

	if err := rows.Scan(&password, &userId); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(givenPassword)); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.InvalidCredentials, http.StatusForbidden, err)
		return err
	}
	return nil
}

// generateTokenPair generates a token pair for the given user.
func generateTokenPair(handler *UserHandler, userId, username string) (*schemas.TokenPairDTO, error) {
	// Generate a token for the user
	token, err := handler.JWTManager.GenerateJWT(userId, username, false)
	if err != nil {
		return nil, err
	}

	refreshToken, err := handler.JWTManager.GenerateJWT(userId, username, true)
	if err != nil {
		return nil, err
	}

	tokenPair := &schemas.TokenPairDTO{
		Token:        token,
		RefreshToken: refreshToken,
	}

	return tokenPair, nil
}

func (handler *UserHandler) RetrieveUserPosts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithDeadline(r.Context(), time.Now().Add(10*time.Second))
	defer func() {
		if err := ctx.Err(); err != nil {
			log.Debug("Context error: ", err)
		}
		cancel()
		log.Debug("Context canceled")
	}()

	// Get the username from URL parameter
	username := chi.URLParam(r, utils.UsernameKey)

	offset, limit, err := utils.ParsePaginationParams(r)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.BadRequest, http.StatusBadRequest, err)
		return
	}

	// Retrieve posts from database
	queryString := "SELECT p.post_id, p.content, p.created_at, p.longitude, p.latitude, p.accuracy " +
		"FROM alpha_schema.posts p JOIN alpha_schema.users u on p.author_id = u.user_id " +
		"WHERE u.username = $1 ORDER BY p.created_at DESC"
	rows, err := handler.DatabaseManager.GetPool().Query(ctx, queryString, username)
	if err != nil {
		utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	// Create a list of posts
	posts := make([]schemas.PostDTO, 0)
	var createdAt pgtype.Timestamptz
	var longitude, latitude pgtype.Float8
	var accuracy pgtype.Int4

	for rows.Next() {
		post := schemas.PostDTO{}
		if err := rows.Scan(&post.PostId, &post.Content, &createdAt, &longitude, &latitude, &accuracy); err != nil {
			utils.WriteAndLogError(ctx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		if longitude.Valid && latitude.Valid {
			post.Location = &schemas.LocationDTO{
				Longitude: longitude.Float64,
				Latitude:  latitude.Float64,
			}
		}

		if accuracy.Valid {
			post.Location.Accuracy = accuracy.Int32
		}

		post.CreationDate = createdAt.Time.Format(time.RFC3339)
		posts = append(posts, post)
	}

	utils.SendPaginatedResponse(ctx, w, posts, offset, limit, len(posts))
}
