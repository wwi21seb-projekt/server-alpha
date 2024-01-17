package handlers

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/http"
	"regexp"
	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type PostHdl interface {
	CreatePost(w http.ResponseWriter, r *http.Request)
	HandleGetFeedRequest(w http.ResponseWriter, r *http.Request)
}

type PostHandler struct {
	DatabaseManager managers.DatabaseMgr
	JWTManager      managers.JWTMgr
	Validator       *utils.Validator
}

var hashtagRegex = regexp.MustCompile(`#\w+`)

func NewPostHandler(databaseManager *managers.DatabaseMgr, jwtManager *managers.JWTMgr) PostHdl {
	return &PostHandler{
		DatabaseManager: *databaseManager,
		JWTManager:      *jwtManager,
		Validator:       utils.GetValidator(),
	}
}

func (handler *PostHandler) CreatePost(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, nil)
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Decode the request body into the registration request struct
	createPostRequest := &schemas.CreatePostRequest{}
	if err := utils.DecodeRequestBody(w, r, createPostRequest); err != nil {
		return
	}

	// Validate the registration request struct using the validator
	if err := utils.ValidateStruct(w, createPostRequest); err != nil {
		return
	}

	// Get the user ID from the JWT token
	claims := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)

	// Create the post
	userId := claims["sub"].(string)
	postId := uuid.New()
	createdAt := time.Now()

	queryString := "INSERT INTO alpha_schema.posts (post_id, author_id, content, created_at) VALUES($1, $2, $3, $4)"
	_, err = tx.Exec(transactionCtx, queryString, postId, userId, createPostRequest.Content, createdAt)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the hashtags
	hashtags := hashtagRegex.FindAllString(createPostRequest.Content, -1)

	for _, hashtag := range hashtags {
		hashtagId := uuid.New()

		queryString := `INSERT INTO alpha_schema.hashtags (hashtag_id, content) VALUES($1, $2) 
						ON CONFLICT (content) DO UPDATE SET content=alpha_schema.hashtags.content 
						RETURNING hashtag_id`
		if err := tx.QueryRow(transactionCtx, queryString, hashtagId, hashtag).Scan(&hashtagId); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		queryString = "INSERT INTO alpha_schema.many_posts_has_many_hashtags (post_id_posts, hashtag_id_hashtags) VALUES($1, $2)"
		if _, err = tx.Exec(transactionCtx, queryString, postId, hashtagId); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	// Get the author
	queryString = "SELECT username, nickname FROM alpha_schema.users WHERE user_id = $1"
	row := tx.QueryRow(transactionCtx, queryString, userId)

	author := &schemas.AuthorDTO{}
	if err := row.Scan(&author.Username, &author.Nickname); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	// Write the response
	utils.WriteAndLogResponse(w, &schemas.PostDTO{
		PostId: postId.String(),
		Author: schemas.AuthorDTO{
			Username:          author.Username,
			Nickname:          author.Nickname,
			ProfilePictureURL: "",
		},
		Content:      createPostRequest.Content,
		CreationDate: createdAt.Format(time.RFC3339),
	}, http.StatusCreated)
}

func (handler *PostHandler) HandleGetFeedRequest(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, nil)
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Determine the feed type
	publicFeedWanted, claims, err := determineFeedType(r, w, handler)
	if err != nil {
		return
	}

	// Retrieve the feed based on the wanted feed type
	posts, records, lastPostId, limit, err := retrieveFeed(transactionCtx, tx, w, r, publicFeedWanted, claims)
	if err != nil {
		return
	}

	// Get the last post ID
	if len(posts) > 0 {
		lastPostId = posts[len(posts)-1].PostId
	}

	// Create pagination DTO
	pagination := &schemas.PostPagination{
		LastPostId: lastPostId,
		Limit:      limit,
		Records:    records,
	}

	paginatedResponse := &schemas.PaginatedResponse{
		Records:    posts,
		Pagination: pagination,
	}

	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
	}

	utils.WriteAndLogResponse(w, paginatedResponse, http.StatusOK)
}

func determineFeedType(r *http.Request, w http.ResponseWriter, handler *PostHandler) (bool, jwt.Claims, error) {
	// Get UserId from JWT token
	authHeader := r.Header.Get("Authorization")
	var claims jwt.Claims
	var err error
	publicFeedWanted := false

	if authHeader == "" {
		publicFeedWanted = true
	} else {
		jwtToken := authHeader[len("Bearer "):]
		claims, err = handler.JWTManager.ValidateJWT(jwtToken)
		if err != nil {
			utils.WriteAndLogError(w, schemas.Unauthorized, http.StatusUnauthorized, err)
			return false, nil, err
		}

		feedType := r.URL.Query().Get(utils.FeedTypeParamKey)
		if feedType == "global" {
			publicFeedWanted = true
		}
	}

	return publicFeedWanted, claims, nil
}

func retrieveFeed(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, r *http.Request, publicFeedWanted bool, claims jwt.Claims) ([]*schemas.PostDTO, int, string, string, error) {
	lastPostId := r.URL.Query().Get(utils.PostIdParamKey)
	limit := r.URL.Query().Get(utils.LimitParamKey)

	if limit == "" {
		limit = "10"
	}

	currentDataQueryIndex := 1
	currentCountQueryIndex := 1
	var userId string
	var countQuery string
	var dataQuery string
	var countQueryArgs []interface{}
	var dataQueryArgs []interface{}

	if !publicFeedWanted {
		userId = claims.(jwt.MapClaims)["sub"].(string)
		countQuery = `SELECT COUNT(*) FROM alpha_schema.posts
    					INNER JOIN alpha_schema.users ON author_id = user_id
    					INNER JOIN alpha_schema.subscriptions ON user_id = subscriptions.subscriber_id
    					WHERE subscriptions.subscriber_id` + fmt.Sprintf(" = $%d", currentCountQueryIndex)
		currentCountQueryIndex++
		dataQuery = `SELECT post_id, username, nickname, profile_picture_url, content, posts.created_at FROM alpha_schema.posts
					INNER JOIN alpha_schema.users ON author_id = user_id
					INNER JOIN alpha_schema.subscriptions ON user_id = subscriptions.subscriber_id
					WHERE subscriptions.subscriber_id` + fmt.Sprintf(" = $%d", currentDataQueryIndex)
		currentDataQueryIndex++

		countQueryArgs = append(countQueryArgs, userId)
		dataQueryArgs = append(dataQueryArgs, userId)
	} else {
		countQuery = "SELECT COUNT(*) FROM alpha_schema.posts"
		dataQuery = `SELECT post_id, username, nickname, profile_picture_url, content, posts.created_at FROM alpha_schema.posts
					INNER JOIN alpha_schema.users ON author_id = user_id`
	}

	// Get the count of posts in the database that match the criteria
	row := tx.QueryRow(ctx, countQuery, countQueryArgs...)

	var count int
	if err := row.Scan(&count); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return nil, 0, "", "", err
	}

	var rows pgx.Rows
	var err error

	if lastPostId == "" {
		// If we don't have a last post ID, we'll return the newest posts
		dataQuery += " ORDER BY created_at DESC LIMIT" + fmt.Sprintf(" $%d", currentDataQueryIndex)
		dataQueryArgs = append(dataQueryArgs, limit)
	} else {
		// If we have a last post ID, we'll return the posts that were created before the last post
		dataQuery += " AND posts.created_at < (SELECT created_at FROM alpha_schema.posts WHERE post_id = " +
			fmt.Sprintf("$%d) ", currentDataQueryIndex) + "ORDER BY created_at DESC LIMIT " +
			fmt.Sprintf("$%d", currentDataQueryIndex+1)
		dataQueryArgs = append(dataQueryArgs, lastPostId, limit)
	}

	rows, err = tx.Query(ctx, dataQuery, dataQueryArgs...)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return nil, 0, "", "", err
	}

	// Iterate over the rows and create the post DTOs
	posts := make([]*schemas.PostDTO, 0)

	for rows.Next() {
		post := &schemas.PostDTO{}
		var createdAt time.Time

		if err := rows.Scan(&post.PostId, &post.Author.Username, &post.Author.Nickname, &post.Author.ProfilePictureURL, &post.Content, &createdAt); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return nil, 0, "", "", err
		}

		post.CreationDate = createdAt.Format(time.RFC3339)
		posts = append(posts, post)
	}

	return posts, count, lastPostId, limit, nil
}
