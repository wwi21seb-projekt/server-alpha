package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wwi21seb-projekt/errors-go/goerrors"
	"github.com/wwi21seb-projekt/server-alpha/internal/managers"
	"github.com/wwi21seb-projekt/server-alpha/internal/schemas"
	"github.com/wwi21seb-projekt/server-alpha/internal/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
)

// SubscriptionHdl defines the interface for handling subscription-related HTTP requests.
type SubscriptionHdl interface {
	HandleGetSubscriptions(ctx *gin.Context)
	Subscribe(ctx *gin.Context)
	Unsubscribe(ctx *gin.Context)
}

// SubscriptionHandler provides methods to handle subscription-related HTTP requests.
type SubscriptionHandler struct {
	DatabaseManager managers.DatabaseMgr
	JwtManager      managers.JWTMgr
}

// NewSubscriptionHandler returns a new SubscriptionHandler with the provided database manager.
func NewSubscriptionHandler(databaseManager *managers.DatabaseMgr) SubscriptionHdl {
	return &SubscriptionHandler{
		DatabaseManager: *databaseManager,
	}
}

// HandleGetSubscriptions handles retrieving subscriptions of a user and sending a paginated response.
// It extracts the username from the URL, fetches subscriptions based on the subscription type, and sends the response.
func (handler *SubscriptionHandler) HandleGetSubscriptions(ctx *gin.Context) {
	// Get the username from the path variable
	username := ctx.Param(utils.UsernameKey)

	// Get pagination parameters
	offset, limit, err := utils.ParsePaginationParams(ctx)
	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.BadRequest, http.StatusBadRequest, err)
		return
	}

	// Get subscription type from query params
	subscriptionType := ctx.Query(utils.SubscriptionTypeParamKey)

	// Get the followers by default
	userTypes := []string{"subscriber", "subscribee"}

	// If the subscription type is following, fetch the users the user is following
	if subscriptionType == "following" {
		userTypes = []string{"subscribee", "subscriber"}
	}

	findUserQuery := "SELECT user_id FROM alpha_schema.users WHERE username = $1"
	rows, err := handler.DatabaseManager.GetPool().Query(ctx, findUserQuery, username)
	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}
	if !rows.Next() {
		utils.WriteAndLogError(ctx, goerrors.UserNotFound, http.StatusNotFound, errors.New("user not found"))
		return
	}

	subscriptionQuery := fmt.Sprintf(`
    SELECT s2.subscription_id, s3.subscription_id, u.username,u.nickname, u.profile_picture_url
	FROM alpha_schema.users AS u
	JOIN alpha_schema.subscriptions AS s1 ON u.user_id = s1.%[1]s_id
	LEFT JOIN alpha_schema.subscriptions AS s2 ON u.user_id = s2.subscribee_id 
    	AND s2.subscriber_id = $1
	LEFT JOIN alpha_schema.subscriptions AS s3 ON u.user_id = s3.subscriber_id 
    	AND s3.subscribee_id = $1
	WHERE s1.%[2]s_id = (SELECT user_id FROM alpha_schema.users WHERE username = $2)
	ORDER BY s1.created_at DESC`, userTypes[0], userTypes[1])

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM alpha_schema.subscriptions s WHERE s.%[1]s_id = "+
		"(SELECT user_id FROM alpha_schema.users WHERE username = $1)", userTypes[1])

	// Get user id from jwt token
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)
	jwtUserId := claims["sub"].(string)

	rows, err = handler.DatabaseManager.GetPool().Query(ctx, subscriptionQuery, jwtUserId, username)
	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	results := make([]schemas.SubscriptionUserDTO, 0)

	for rows.Next() {
		subscription := schemas.SubscriptionUserDTO{}
		followerId, followingId := uuid.UUID{}, uuid.UUID{}

		if err := rows.Scan(&followingId, &followerId, &subscription.Username, &subscription.Nickname, &subscription.ProfilePictureUrl); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		if followingId != uuid.Nil {
			followingIdStr := followingId.String()
			subscription.FollowingId = &followingIdStr
		}
		if followerId != uuid.Nil {
			followerIdStr := followerId.String()
			subscription.FollowerId = &followerIdStr
		}

		results = append(results, subscription)
	}

	row := handler.DatabaseManager.GetPool().QueryRow(ctx, countQuery, username)
	var totalSubscriptions int
	if err := row.Scan(&totalSubscriptions); err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Send response
	utils.SendPaginatedResponse(ctx, results, offset, limit, totalSubscriptions)
}

// Subscribe handles creating a new subscription between the current user and the specified user in the request.
// It validates the request, checks if the subscription already exists, creates a new subscription if it doesn't exist,
// and sends the subscription details in the response.
func (handler *SubscriptionHandler) Subscribe(ctx *gin.Context) {
	// Begin a new transaction
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(ctx, tx, err)

	// Decode the request body into the subscription request struct
	subscriptionRequest := ctx.Value(utils.SanitizedPayloadKey.String()).(*schemas.SubscriptionRequest)

	// Get subscribeeId from request body
	queryString := "SELECT user_id FROM alpha_schema.users WHERE username = $1"
	row := tx.QueryRow(ctx, queryString, subscriptionRequest.Following)
	var subscribeeId string
	if err = row.Scan(&subscribeeId); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(ctx, goerrors.UserNotFound, http.StatusNotFound, err)
			return
		}

		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the user ID from the JWT token
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)
	jwtUserId := claims["sub"].(string)
	jwtUsername := claims["username"].(string)

	// Check and throw error if the user wants to subscribe to himself
	if jwtUserId == subscribeeId {
		utils.WriteAndLogError(ctx, goerrors.SubscriptionSelfFollow, http.StatusNotAcceptable,
			errors.New("user cannot subscribe to himself"))
		return
	}

	// Check and throw error if the user is already subscribed to the user he wants to subscribe to
	queryString = "SELECT subscription_id FROM alpha_schema.subscriptions WHERE subscriber_id = $1 AND subscribee_id = $2"
	rows := tx.QueryRow(ctx, queryString, jwtUserId, subscribeeId)
	var subscriptionId uuid.UUID

	if err := rows.Scan(&subscriptionId); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	if subscriptionId != uuid.Nil {
		// User is already subscribed, since the subscriptionId is not nil
		utils.WriteAndLogError(ctx, goerrors.SubscriptionAlreadyExists, http.StatusConflict,
			errors.New("subscription already exists"))
		return
	}

	// Subscribe the user
	queryString = "INSERT INTO alpha_schema.subscriptions (subscription_id, subscriber_id, subscribee_id, created_at) VALUES ($1, $2, $3, $4)"
	subscriptionId = uuid.New()
	createdAt := time.Now()
	if _, err := tx.Exec(ctx, queryString, subscriptionId, jwtUserId, subscribeeId, createdAt); err != nil {
		log.Errorf("error while inserting subscription: %v", err)
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
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
	if err := utils.CommitTransaction(ctx, tx); err != nil {
		return
	}

	// Send success response
	utils.WriteAndLogResponse(ctx, subscriptionDto, http.StatusCreated)
}

// Unsubscribe handles removing a subscription between the current user and the user specified by the subscription ID in the URL.
// It validates the user's authorization to delete the subscription and removes the subscription if authorized.
func (handler *SubscriptionHandler) Unsubscribe(ctx *gin.Context) {
	// Begin a new transaction
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(ctx, tx, err)

	// Get the user ID from the JWT token
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)
	jwtUserId := claims["sub"].(string)

	// Get subscriptionId from path
	subscriptionId := ctx.Param(utils.SubscriptionIdKey)

	// Get the subscribeeId and subscriberId from the subscriptionId
	queryString := "SELECT subscriber_id, subscribee_id FROM alpha_schema.subscriptions WHERE subscription_id = $1"
	row := tx.QueryRow(ctx, queryString, subscriptionId)
	var subscriberId, subscribeeId string
	if err := row.Scan(&subscriberId, &subscribeeId); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(ctx, goerrors.SubscriptionNotFound, http.StatusNotFound,
				errors.New("subscription not found"))
			return
		}
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Check and throw error if user wants to delete someone else's subscription
	if subscriberId != jwtUserId {
		utils.WriteAndLogError(ctx, goerrors.UnsubscribeForbidden, http.StatusForbidden,
			errors.New("you can only delete your own subscriptions"))
		return
	}

	// Unsubscribe the user
	queryString = "DELETE FROM alpha_schema.subscriptions WHERE subscription_id = $1"
	if _, err := tx.Exec(ctx, queryString, subscriptionId); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(ctx, goerrors.SubscriptionNotFound, http.StatusNotFound,
				errors.New("subscription not found"))
			return
		}
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(ctx, tx); err != nil {
		return
	}

	ctx.Status(http.StatusNoContent)
}
