package handlers

import (
	"context"
	"github.com/jackc/pgx/v5"
	"net/http"
	"regexp"
	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type PostHdl interface {
	CreatePost(w http.ResponseWriter, r *http.Request)
	GetFeed(w http.ResponseWriter, r *http.Request)
}

type PostHandler struct {
	DatabaseManager managers.DatabaseMgr
	JWTManager      managers.JWTMgr
	Validator       *utils.Validator
}

var hashtagRegex = regexp.MustCompile(`#\w+`)

func NewPostHandler(databaseManager *managers.DatabaseMgr) PostHdl {
	return &PostHandler{
		DatabaseManager: *databaseManager,
		Validator:       utils.GetValidator(),
	}
}

func (handler *PostHandler) CreatePost(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
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
		CreationDate: createdAt.String(),
	}, http.StatusCreated)
}

func (handler *PostHandler) GetFeed(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Get UserId from JWT token
	authHeader := r.Header.Get("Authorization")
	var claims jwt.Claims
	publicFeedWanted := false

	if authHeader == "" {
		publicFeedWanted = true
	} else {
		jwtToken := authHeader[len("Bearer "):]
		claims, err = handler.JWTManager.ValidateJWT(jwtToken)
		if err != nil {
			utils.WriteAndLogError(w, schemas.Unauthorized, http.StatusUnauthorized, err)
			return
		}

		feedType := r.URL.Query().Get(utils.FeedTypeParamKey)
		if feedType == "global" {
			publicFeedWanted = true
		}
	}

	if publicFeedWanted {
		getPublicFeed(transactionCtx, tx, w, r)
		return
	}

	getPrivateFeed(transactionCtx, tx, w, r, claims)
}

func getPrivateFeed(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, r *http.Request, claims jwt.Claims) {
	lastPostId := r.URL.Query().Get(utils.PostIdParamKey)
	limit := r.URL.Query().Get(utils.LimitParamKey)
	userId := claims.(jwt.MapClaims)["sub"]

	// Get the count of posts in the database that match the criteria
	queryString := `SELECT COUNT(*) FROM alpha_schema.posts
    					INNER JOIN alpha_schema.users ON author_id = user_id
    					INNER JOIN alpha_schema.subscriptions ON user_id = subscriptions.subscriber_id
    					WHERE subscriptions.subscriber_id = $1`
	row := tx.QueryRow(ctx, queryString, userId)

	var count int
	if err := row.Scan(&count); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	var rows pgx.Rows
	var err error

	if lastPostId == "" {
		// If we don't have a last post ID, we'll return the newest posts
		queryString = `SELECT post_id, username, nickname, profile_picture_url, content, posts.created_at FROM alpha_schema.posts
					INNER JOIN alpha_schema.users ON author_id = user_id
					INNER JOIN alpha_schema.subscriptions ON user_id = subscriptions.subscriber_id
					WHERE subscriptions.subscriber_id = $1
					ORDER BY created_at DESC LIMIT $2`
		rows, err = tx.Query(ctx, queryString, userId, limit)
	} else {
		// If we have a last post ID, we'll return the posts that were created before the last post
		queryString = `SELECT post_id, username, nickname, profile_picture_url, content, posts.created_at FROM alpha_schema.posts
					INNER JOIN alpha_schema.users ON author_id = user_id
					INNER JOIN alpha_schema.subscriptions ON user_id = subscriptions.subscriber_id
					WHERE subscriptions.subscriber_id = $1
					AND posts.created_at < (SELECT created_at FROM alpha_schema.posts WHERE post_id = $2)
					ORDER BY created_at DESC LIMIT $3`
		rows, err = tx.Query(ctx, queryString, userId, lastPostId, limit)
	}

	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Iterate over the rows and create the post DTOs
	intLimit, err := strconv.Atoi(limit)
	if err != nil {
		utils.WriteAndLogError(w, schemas.BadRequest, http.StatusBadRequest, err)
		return
	}

	posts := make([]*schemas.PostDTO, intLimit)

	for rows.Next() {
		post := &schemas.PostDTO{}
		if err := rows.Scan(&post.PostId, &post.Author.Username, &post.Author.Nickname, &post.Author.ProfilePictureURL, &post.Content, &post.CreationDate); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		posts = append(posts, post)
	}

	// Get the last post ID
	if len(posts) > 0 {
		lastPostId = posts[len(posts)-1].PostId
	}

	// Create pagination DTO
	pagination := &schemas.PostPagination{
		LastPostId: lastPostId,
		Limit:      limit,
		Records:    count,
	}

	paginatedResponse := &schemas.PaginatedResponse{
		Records:    posts,
		Pagination: pagination,
	}

	if err := utils.CommitTransaction(w, nil, ctx, nil); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
	}

	utils.WriteAndLogResponse(w, paginatedResponse, http.StatusOK)
}

func getPublicFeed(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, r *http.Request) {
	lastPostId := r.URL.Query().Get(utils.PostIdParamKey)
	limit := r.URL.Query().Get(utils.LimitParamKey)

	// Get the count of posts in the database
	queryString := "SELECT COUNT(*) FROM alpha_schema.posts"
	row := tx.QueryRow(ctx, queryString)

	var count int
	if err := row.Scan(&count); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Select the limit newest posts from the database
	if limit == "" {
		limit = "10"
	}

	if lastPostId == "" {
		// If we don't have a last post ID, we'll return the newest posts
		queryString = `SELECT post_id, username, nickname, profile_picture_url, content, posts.created_at FROM alpha_schema.posts
					INNER JOIN alpha_schema.users ON author_id = user_id
					ORDER BY created_at DESC LIMIT $1`
	} else {
		// If we have a last post ID, we'll return the posts that were created before the last post
		queryString = `SELECT post_id, username, nickname, content, posts.created_at FROM alpha_schema.posts
					INNER JOIN alpha_schema.users ON author_id = user_id 
				   	WHERE posts.created_at < (SELECT created_at FROM alpha_schema.posts WHERE post_id = $1)
					ORDER BY created_at DESC LIMIT $2`
	}

	rows, err := tx.Query(ctx, queryString, lastPostId, limit)
	if err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Iterate over the rows and create the post DTOs
	posts := make([]*schemas.PostDTO, 0)
	for rows.Next() {
		post := &schemas.PostDTO{}
		if err := rows.Scan(&post.PostId, &post.Author.Username, &post.Author.Nickname, &post.Author.ProfilePictureURL, &post.Content, &post.CreationDate); err != nil {
			utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		posts = append(posts, post)
	}

	// Get the last post ID
	if len(posts) > 0 {
		lastPostId = posts[len(posts)-1].PostId
	}

	// Create pagination DTO
	pagination := &schemas.PostPagination{
		LastPostId: lastPostId,
		Limit:      limit,
		Records:    count,
	}

	paginatedResponse := &schemas.PaginatedResponse{
		Records:    posts,
		Pagination: pagination,
	}

	if err := utils.CommitTransaction(w, nil, ctx, nil); err != nil {
		utils.WriteAndLogError(w, schemas.DatabaseError, http.StatusInternalServerError, err)
	}

	utils.WriteAndLogResponse(w, paginatedResponse, http.StatusOK)
}
