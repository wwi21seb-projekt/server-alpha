package handlers

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	log "github.com/sirupsen/logrus"
	"net/http"
	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"time"
)

type SubscriptionHdl interface {
	HandleGetSubscriptions(w http.ResponseWriter, r *http.Request)
}

type SubscriptionHandler struct {
	DatabaseManager managers.DatabaseMgr
	JwtManager      managers.JWTMgr
}

func NewSubscriptionHandler(databaseManager *managers.DatabaseMgr, jwtManager *managers.JWTMgr) SubscriptionHdl {
	return &SubscriptionHandler{
		DatabaseManager: *databaseManager,
		JwtManager:      *jwtManager,
	}
}

func (handler *SubscriptionHandler) HandleGetSubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithDeadline(r.Context(), time.Now().Add(1000*time.Second))
	defer func() {
		if err := ctx.Err(); err != nil {
			log.Debug("Context error: ", err)
		}
		cancel()
		log.Debug("Context canceled")
	}()

	// Get the user ID from the JWT token
	claims := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)
	jwtUserId := claims["sub"].(string)

	// Get pagination parameters
	offset, limit, err := utils.ParsePaginationParams(r)
	if err != nil {
		utils.WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, err)
		return
	}

	var queryString string
	var createdAt pgtype.Timestamptz
	results := make([]any, 0, limit)
	var totalResults int
	// read from query parameter
	subscriptionType := r.URL.Query().Get("type")

	if subscriptionType == "following" {
		queryString = `SELECT s.subscription_id, s.created_at, u.username, u.nickname, u.profile_picture_url 
			FROM alpha_schema.subscriptions s INNER JOIN alpha_schema.users u ON s.subscriber_id = u.user_id 
			WHERE u.user_id = $1 ORDER BY s.created_at DESC OFFSET $2 LIMIT $3`
		rows, err := handler.DatabaseManager.GetPool().Query(ctx, queryString, jwtUserId, offset, limit)
		if err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		for rows.Next() {
			// Get following from jwtUserId
			following := schemas.FollowingDTO{}
			followingUser := schemas.AuthorDTO{}
			err := rows.Scan(&following.SubscriptionId, &createdAt, &followingUser.Username, &followingUser.Nickname, &followingUser.ProfilePictureURL)
			if err != nil {
				utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
				return
			}

			following.CreationDate = createdAt.Time.Format(time.RFC3339)
			following.Following = followingUser
			results = append(results, following)
		}

		// Get total number of following
		queryString = `SELECT COUNT(*) FROM alpha_schema.subscriptions s 
    					INNER JOIN alpha_schema.users u ON s.subscriber_id = u.user_id WHERE u.user_id = $1`
		row := handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, jwtUserId)
		if err := row.Scan(&totalResults); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

	} else {
		queryString = `SELECT s.subscription_id, s.created_at, u.username, u.nickname, u.profile_picture_url 
			FROM alpha_schema.subscriptions s INNER JOIN alpha_schema.users u ON s.subscribee_id = u.user_id 
			WHERE u.user_id = $1 ORDER BY s.created_at DESC OFFSET $2 LIMIT $3`
		rows, err := handler.DatabaseManager.GetPool().Query(ctx, queryString, jwtUserId, offset, limit)
		if err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		for rows.Next() {
			// Get followers from jwtUserId
			var follower schemas.FollowerDTO
			var followerUser schemas.AuthorDTO
			err := rows.Scan(&follower.SubscriptionId, &createdAt, &followerUser.Username, &followerUser.Nickname, &followerUser.ProfilePictureURL)
			if err != nil {
				utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
				return
			}
			follower.CreationDate = createdAt.Time.Format(time.RFC3339)
			follower.Follower = followerUser
			results = append(results, follower)
		}

		// Get total number of followers
		queryString = `SELECT COUNT(*) FROM alpha_schema.subscriptions s 
    					INNER JOIN alpha_schema.users u ON s.subscribee_id = u.user_id WHERE u.user_id = $1`
		row := handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, jwtUserId)
		if err := row.Scan(&totalResults); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	// Send response
	utils.SendPaginatedResponse(w, results, offset, limit, totalResults)
}
