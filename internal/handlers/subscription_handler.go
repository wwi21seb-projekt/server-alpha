package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	log "github.com/sirupsen/logrus"
)

type SubscriptionHdl interface {
	HandleGetSubscriptions(w http.ResponseWriter, r *http.Request)
	Subscribe(w http.ResponseWriter, r *http.Request)
	Unsubscribe(w http.ResponseWriter, r *http.Request)
}

type SubscriptionHandler struct {
	DatabaseManager managers.DatabaseMgr
	JwtManager      managers.JWTMgr
}

func NewSubscriptionHandler(databaseManager *managers.DatabaseMgr) SubscriptionHdl {
	return &SubscriptionHandler{
		DatabaseManager: *databaseManager,
	}
}

// HandleGetSubscriptions retrieves the subscriptions of a user and sends a paginated response.
func (handler *SubscriptionHandler) HandleGetSubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithDeadline(r.Context(), time.Now().Add(10*time.Second))
	defer func() {
		if err := ctx.Err(); err != nil {
			log.Debug("Context error: ", err)
		}
		cancel()
		log.Debug("Context canceled")
	}()

	// Get the username from the path variable
	username := chi.URLParam(r, utils.UsernameKey)
	if username == "" {
		utils.WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, errors.New("username missing"))
		return
	}

	// Get pagination parameters
	offset, limit, err := utils.ParsePaginationParams(r)
	if err != nil {
		utils.WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, err)
		return
	}

	// Get subscription type from query params
	subscriptionType := r.URL.Query().Get(utils.SubscriptionTypeParamKey)

	// Get the followers by default
	userTypes := []string{"subscriber", "subscribee"}

	// If the subscription type is following, fetch the users the user is following
	if subscriptionType == "following" {
		userTypes = []string{"subscribee", "subscriber"}
	}

	findUserQuery := fmt.Sprintf("SELECT user_id FROM alpha_schema.users WHERE username = $1")
	rows, err := handler.DatabaseManager.GetPool().Query(ctx, findUserQuery, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}
	if !rows.Next() {
		utils.WriteAndLogError(w, schemas.UserNotFound, http.StatusNotFound, errors.New("user not found"))
		return
	}

	subscriptionQuery := fmt.Sprintf(`
    SELECT s.subscription_id, s.created_at, u.username, u.nickname, u.profile_picture_url 
    FROM alpha_schema.subscriptions s 
    INNER JOIN alpha_schema.users u ON s.%[1]s_id = u.user_id
    WHERE s.%[2]s_id = (SELECT user_id FROM alpha_schema.users WHERE username = $1) 
    ORDER BY s.created_at DESC`, userTypes[0], userTypes[1])

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM alpha_schema.subscriptions s WHERE s.%[1]s_id = "+
		"(SELECT user_id FROM alpha_schema.users WHERE username = $1)", userTypes[1])

	rows, err = handler.DatabaseManager.GetPool().Query(ctx, subscriptionQuery, username)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	results := make([]schemas.SubscriptionUserDTO, 0)
	var subscriptionDate pgtype.Timestamptz

	for rows.Next() {
		subscription := schemas.SubscriptionUserDTO{}
		if err := rows.Scan(&subscription.SubscriptionId, &subscriptionDate, &subscription.User.Username, &subscription.User.Nickname, &subscription.User.ProfilePictureURL); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		subscription.SubscriptionDate = subscriptionDate.Time.Format(time.RFC3339)
		results = append(results, subscription)
	}

	row := handler.DatabaseManager.GetPool().QueryRow(ctx, countQuery, username)
	var totalSubscriptions int
	if err := row.Scan(&totalSubscriptions); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Send response
	utils.SendPaginatedResponse(w, results, offset, limit, totalSubscriptions)
}

// Subscribe creates a new subscription between the current user and the username specified in the request body.
func (handler *SubscriptionHandler) Subscribe(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Decode the request body into the subscription request struct
	subscriptionRequest := &schemas.SubscriptionRequest{}
	if err := utils.DecodeRequestBody(w, r, subscriptionRequest); err != nil {
		return
	}

	// Validate the subscription request struct using the validator
	if err := utils.ValidateStruct(w, subscriptionRequest); err != nil {
		return
	}

	// Get subscribeeId from request body
	queryString := "SELECT user_id FROM alpha_schema.users WHERE username = $1"
	row := tx.QueryRow(transactionCtx, queryString, subscriptionRequest.Following)
	var subscribeeId string
	if err := row.Scan(&subscribeeId); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(w, schemas.UserNotFound, http.StatusNotFound, err)
			return
		}

		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the user ID from the JWT token
	claims := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)
	jwtUserId := claims["sub"].(string)
	jwtUsername := claims["username"].(string)

	// Check and throw error if the user wants to subscribe to himself
	if jwtUserId == subscribeeId {
		utils.WriteAndLogError(w, schemas.SubscriptionSelfFollow, http.StatusNotAcceptable, errors.New("user cannot subscribe to himself"))
		return
	}

	// Check and throw error if the user is already subscribed to the user he wants to subscribe to
	queryString = "SELECT subscription_id FROM alpha_schema.subscriptions WHERE subscriber_id = $1 AND subscribee_id = $2"
	rows := tx.QueryRow(transactionCtx, queryString, jwtUserId, subscribeeId)
	var subscriptionId uuid.UUID

	if err := rows.Scan(&subscriptionId); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	if subscriptionId != uuid.Nil {
		// User is already subscribed, since the subscriptionId is not nil
		utils.WriteAndLogError(w, schemas.SubscriptionAlreadyExists, http.StatusConflict, errors.New("subscription already exists"))
		return
	}

	// Subscribe the user
	queryString = "INSERT INTO alpha_schema.subscriptions (subscription_id, subscriber_id, subscribee_id, created_at) VALUES ($1, $2, $3, $4)"
	subscriptionId = uuid.New()
	createdAt := time.Now()
	if _, err := tx.Exec(transactionCtx, queryString, subscriptionId, jwtUserId, subscribeeId, createdAt); err != nil {
		log.Errorf("error while inserting subscription: %v", err)
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Send the subscription to the user
	subscriptionDto := &schemas.SubscriptionDTO{
		SubscriptionId:   subscriptionId,
		SubscriptionDate: createdAt.Format(time.RFC3339),
		Following:        subscriptionRequest.Following,
		Follower:         jwtUsername,
	}

	// Commit the transaction
	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	// Send success response
	utils.WriteAndLogResponse(w, subscriptionDto, http.StatusCreated)
}

// Unsubscribe removes a subscription between the current user and the user specified by the subscription ID.
func (handler *SubscriptionHandler) Unsubscribe(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Get the user ID from the JWT token
	claims := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)
	jwtUserId := claims["sub"].(string)

	// Get subscriptionId from path
	subscriptionId := chi.URLParam(r, utils.SubscriptionIdKey)

	// Get the subscribeeId and subscriberId from the subscriptionId
	queryString := "SELECT subscriber_id, subscribee_id FROM alpha_schema.subscriptions WHERE subscription_id = $1"
	row := tx.QueryRow(transactionCtx, queryString, subscriptionId)
	var subscriberId, subscribeeId string
	if err := row.Scan(&subscriberId, &subscribeeId); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(w, schemas.SubscriptionNotFound, http.StatusNotFound, errors.New("subscription not found"))
			return
		}
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Check and throw error if user wants to delete someone else's subscription
	if subscriberId != jwtUserId {
		utils.WriteAndLogError(w, schemas.UnsubscribeForbidden, http.StatusForbidden, errors.New("you can only delete your own subscriptions"))
		return
	}

	// Unsubscribe the user
	queryString = "DELETE FROM alpha_schema.subscriptions WHERE subscription_id = $1"
	if _, err := tx.Exec(transactionCtx, queryString, subscriptionId); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(w, schemas.SubscriptionNotFound, http.StatusNotFound, errors.New("subscription not found"))
			return
		}
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
