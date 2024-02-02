// Package handlers implements the handlers for the different routes of the server to handle the incoming HTTP requests.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"regexp"
	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// PostHdl defines the interface for handling post-related HTTP requests.
type PostHdl interface {
	CreatePost(w http.ResponseWriter, r *http.Request)
	DeletePost(w http.ResponseWriter, r *http.Request)
	QueryPosts(w http.ResponseWriter, r *http.Request)
	HandleGetFeedRequest(w http.ResponseWriter, r *http.Request)
}

// PostHandler provides methods to handle post-related HTTP requests.
type PostHandler struct {
	DatabaseManager managers.DatabaseMgr
	JWTManager      managers.JWTMgr
	Validator       *utils.Validator
}

var hashtagRegex = regexp.MustCompile(`#\w+`) // Regular expression to find hashtags in content.

// NewPostHandler returns a new PostHandler with the provided managers and validator.
func NewPostHandler(databaseManager *managers.DatabaseMgr, jwtManager *managers.JWTMgr) PostHdl {
	return &PostHandler{
		DatabaseManager: *databaseManager,
		JWTManager:      *jwtManager,
		Validator:       utils.GetValidator(),
	}
}

// CreatePost handles the creation of a new post. It begins a new transaction, validates the request payload,
// extracts the user ID from JWT token, inserts the post data into the database, handles hashtags,
// and commits the transaction.
func (handler *PostHandler) CreatePost(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError,
			errors.New("error beginning transaction"))
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Decode the request body into the registration request struct
	createPostRequest := &schemas.CreatePostRequest{}
	if err := utils.DecodeRequestBody(transactionCtx, w, r, createPostRequest); err != nil {
		return
	}

	// Validate the registration request struct using the validator
	if err := utils.ValidateStruct(transactionCtx, w, createPostRequest); err != nil {
		return
	}

	// Get the user ID from the JWT token
	claims := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)

	// Create the post
	userId := claims["sub"].(string)
	postId := uuid.New()
	createdAt := time.Now()
	locationGiven := true

	if createPostRequest.Location == (schemas.LocationDTO{}) {
		locationGiven = false
	}

	wantedValues := []string{"post_id", "author_id", "content", "created_at"}
	wantedPlaceholders := []string{"$1", "$2", "$3", "$4"}
	queryArgs := []interface{}{postId, userId, createPostRequest.Content, createdAt}

	if locationGiven {
		wantedValues = append(wantedValues, "longitude", "latitude", "accuracy")
		wantedPlaceholders = append(wantedPlaceholders, "$5", "$6", "$7")
		queryArgs = append(queryArgs, createPostRequest.Location.Longitude, createPostRequest.Location.Latitude,
			createPostRequest.Location.Accuracy)
	}

	queryString := fmt.Sprintf("INSERT INTO alpha_schema.posts (%s) VALUES(%s)", strings.Join(wantedValues, ","),
		strings.Join(wantedPlaceholders, ","))

	_, err = tx.Exec(transactionCtx, queryString, queryArgs...)
	if err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
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
			utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		queryString = "INSERT INTO alpha_schema.many_posts_has_many_hashtags (post_id_posts, hashtag_id_hashtags) VALUES($1, $2)"
		if _, err = tx.Exec(transactionCtx, queryString, postId, hashtagId); err != nil {
			utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	// Get the author
	queryString = "SELECT username, nickname FROM alpha_schema.users WHERE user_id = $1"
	row := tx.QueryRow(transactionCtx, queryString, userId)

	author := &schemas.AuthorDTO{}
	if err := row.Scan(&author.Username, &author.Nickname); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	// Create the post DTO
	post := &schemas.PostDTO{
		PostId: postId.String(),
		Author: schemas.AuthorDTO{
			Username:          author.Username,
			Nickname:          author.Nickname,
			ProfilePictureURL: "",
		},
		Content:      createPostRequest.Content,
		CreationDate: createdAt.Format(time.RFC3339),
	}

	if locationGiven {
		post.Location = &createPostRequest.Location
	}

	// Write the response
	utils.WriteAndLogResponse(transactionCtx, w, post, http.StatusCreated)
}

// DeletePost handles the deletion of a post by ID. It verifies the user's authorization to delete the post,
// deletes the post and its associated hashtags if they are no longer used, and commits the transaction.
func (handler *PostHandler) DeletePost(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, nil)
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Get the post ID from the URL
	postId := chi.URLParam(r, utils.PostIdParamKey)

	// Get the user ID from the JWT token
	claims := r.Context().Value(utils.ClaimsKey).(jwt.MapClaims)

	// Check if the user is the author of the post
	queryString := "SELECT author_id, content FROM alpha_schema.posts WHERE post_id = $1"
	row := tx.QueryRow(transactionCtx, queryString, postId)

	var authorId string
	var content string
	if err := row.Scan(&authorId, &content); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(transactionCtx, w, schemas.PostNotFound, http.StatusNotFound, err)
			return
		}

		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	userId := claims["sub"].(string)
	if userId != authorId {
		utils.WriteAndLogError(transactionCtx, w, schemas.DeletePostForbidden, http.StatusForbidden, errors.New("user is not the author of the post"))
		return
	}

	// Delete the post
	queryString = "DELETE FROM alpha_schema.posts WHERE post_id = $1"
	if _, err = tx.Exec(transactionCtx, queryString, postId); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Delete the hashtags that are not used by any other post
	hashtags := hashtagRegex.FindAllString(content, -1)
	queryString = `DELETE FROM alpha_schema.hashtags WHERE hashtags.content = $1 
					AND NOT EXISTS 
					    (SELECT 1 FROM alpha_schema.many_posts_has_many_hashtags 
					WHERE many_posts_has_many_hashtags.hashtag_id_hashtags = 
					      (SELECT hashtag_id FROM alpha_schema.hashtags WHERE hashtags.content = $1))`

	for _, hashtag := range hashtags {
		if _, err = tx.Exec(transactionCtx, queryString, hashtag); err != nil {
			utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	// Commit the transaction
	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		return
	}

	// Write the response
	utils.WriteAndLogResponse(transactionCtx, w, nil, http.StatusNoContent)
}

// QueryPosts handles querying of posts based on the provided query parameters. It builds the database query dynamically,
// retrieves the count and records of matching posts, and creates a paginated response.
func (handler *PostHandler) QueryPosts(w http.ResponseWriter, r *http.Request) {
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, nil)
		return
	}
	var err error
	defer utils.RollbackTransaction(w, tx, transactionCtx, cancel, err)

	// Get the query parameters
	queryParams := r.URL.Query()
	q := queryParams.Get(utils.QueryParamKey)
	limit, lastPostId := parseLimitAndPostId(queryParams.Get(utils.LimitParamKey), queryParams.Get(utils.PostIdParamKey))

	// Build query based on if we have a last post ID or not
	dataQueryArgs := make([]interface{}, 0)
	countQueryArgs := make([]interface{}, 0)

	queryString := "SELECT %s " +
		"FROM alpha_schema.posts " +
		"INNER JOIN alpha_schema.users ON author_id = user_id " +
		"INNER JOIN alpha_schema.many_posts_has_many_hashtags ON post_id = post_id_posts " +
		"INNER JOIN alpha_schema.hashtags ON hashtag_id = hashtag_id_hashtags " +
		"WHERE hashtags.content LIKE $1 "

	dataQueryArgs = append(dataQueryArgs, "%"+q+"%")
	countQueryArgs = append(countQueryArgs, "%"+q+"%")
	countQueryString := fmt.Sprintf(queryString, "COUNT(DISTINCT posts.post_id)")

	if lastPostId == "" {
		queryString += "ORDER BY created_at DESC LIMIT $2"
	} else {
		queryString += "AND posts.created_at < (SELECT created_at FROM alpha_schema.posts WHERE post_id = $2) " +
			"ORDER BY created_at DESC LIMIT $3"
		dataQueryArgs = append(dataQueryArgs, lastPostId)
	}

	dataQueryArgs = append(dataQueryArgs, limit)
	dataQueryString := fmt.Sprintf(queryString, "DISTINCT posts.post_id, username, nickname, profile_picture_url, "+
		"posts.content, posts.created_at, posts.longitude, posts.latitude, posts.accuracy")

	// Get count and posts
	count, posts, customErr, statusCode, err := retrieveCountAndRecords(transactionCtx, tx, countQueryString,
		countQueryArgs, dataQueryString, dataQueryArgs)
	if err != nil {
		utils.WriteAndLogError(transactionCtx, w, customErr, statusCode, err)
		return
	}

	// Create paginated response and send it
	paginatedResponse := createPaginatedResponse(posts, lastPostId, limit, count)

	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
	}

	utils.WriteAndLogResponse(transactionCtx, w, paginatedResponse, http.StatusOK)
}

// HandleGetFeedRequest handles requests to retrieve a feed. It determines the feed type (public or private),
// retrieves the appropriate feed based on the user's subscriptions if needed, and creates a paginated response.
func (handler *PostHandler) HandleGetFeedRequest(w http.ResponseWriter, r *http.Request) {
	// Begin a new transaction
	tx, transactionCtx, cancel := utils.BeginTransaction(w, r, handler.DatabaseManager.GetPool())
	if tx == nil || transactionCtx == nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, nil)
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

	paginatedResponse := createPaginatedResponse(posts, lastPostId, limit, records)

	if err := utils.CommitTransaction(w, tx, transactionCtx, cancel); err != nil {
		utils.WriteAndLogError(transactionCtx, w, schemas.DatabaseError, http.StatusInternalServerError, err)
	}

	utils.WriteAndLogResponse(transactionCtx, w, paginatedResponse, http.StatusOK)
}

// CreatePaginatedResponse creates a paginated response for a list of posts based on the provided parameters.
func createPaginatedResponse(posts []*schemas.PostDTO, lastPostId, limit string, records int) *schemas.PaginatedResponse {
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
	return paginatedResponse
}

// DetermineFeedType determines the type of feed requested based on the presence and content of the JWT token
// and the 'feedType' query parameter.
func determineFeedType(r *http.Request, w http.ResponseWriter, handler *PostHandler) (bool, jwt.Claims, error) {
	// Get UserId from JWT token
	authHeader := r.Header.Get("Authorization")
	var claims jwt.Claims
	var err error
	publicFeedWanted := false

	if authHeader == "" {
		publicFeedWanted = true
	} else {
		if !strings.HasPrefix(authHeader, "Bearer ") || len(authHeader) <= len("Bearer ") {
			err = errors.New("invalid authorization header")
			utils.WriteAndLogError(r.Context(), w, schemas.InvalidToken, http.StatusBadRequest, err)
			return false, nil, err
		}

		jwtToken := authHeader[len("Bearer "):]
		claims, err = handler.JWTManager.ValidateJWT(jwtToken)
		if err != nil {
			utils.WriteAndLogError(r.Context(), w, schemas.Unauthorized, http.StatusUnauthorized, err)
			return false, nil, err
		}

		feedType := r.URL.Query().Get(utils.FeedTypeParamKey)
		if feedType == "global" {
			publicFeedWanted = true
		}
	}

	return publicFeedWanted, claims, nil
}

// RetrieveFeed retrieves the appropriate feed based on whether a public or private feed is requested.
// It builds the database query dynamically based on the feed type and user input, retrieves the posts,
// and returns the posts along with pagination details.
func retrieveFeed(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, r *http.Request, publicFeedWanted bool,
	claims jwt.Claims) ([]*schemas.PostDTO, int, string, string, error) {
	queryParams := r.URL.Query()
	limit, lastPostId := parseLimitAndPostId(queryParams.Get(utils.LimitParamKey), queryParams.Get(utils.PostIdParamKey))

	currentDataQueryIndex := 1
	currentCountQueryIndex := 1
	var userId string
	var countQuery string
	var dataQuery string
	var countQueryArgs []interface{}
	var dataQueryArgs []interface{}

	// Dynamically build queries based on user input
	if !publicFeedWanted {
		userId = claims.(jwt.MapClaims)["sub"].(string)
		countQuery = `SELECT COUNT(*) FROM alpha_schema.posts
    					INNER JOIN alpha_schema.subscriptions ON posts.author_id = subscriptions.subscribee_id
    					INNER JOIN alpha_schema.users ON posts.author_id = users.user_id    					
    					WHERE subscriptions.subscriber_id` + fmt.Sprintf(" = $%d", currentCountQueryIndex)
		currentCountQueryIndex++
		dataQuery = `
			SELECT post_id, username, nickname, profile_picture_url, content, posts.created_at, posts.longitude, posts.latitude, posts.accuracy 
			FROM alpha_schema.posts
			INNER JOIN alpha_schema.subscriptions ON posts.author_id = subscriptions.subscribee_id
			INNER JOIN alpha_schema.users ON posts.author_id = users.user_id				
			WHERE subscriptions.subscriber_id` + fmt.Sprintf(" = $%d", currentDataQueryIndex)
		currentDataQueryIndex++

		countQueryArgs = append(countQueryArgs, userId)
		dataQueryArgs = append(dataQueryArgs, userId)
	} else {
		countQuery = "SELECT COUNT(*) FROM alpha_schema.posts"
		dataQuery = `
			SELECT post_id, username, nickname, profile_picture_url, content, posts.created_at, posts.longitude, posts.latitude, posts.accuracy 
			FROM alpha_schema.posts
			INNER JOIN alpha_schema.users ON author_id = user_id`
	}

	// Append additional clauses to the data query based on the lastPostId
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

	count, posts, customErr, statusCode, err := retrieveCountAndRecords(ctx, tx, countQuery, countQueryArgs, dataQuery, dataQueryArgs)
	if err != nil {
		utils.WriteAndLogError(ctx, w, customErr, statusCode, err)
		return nil, 0, "", "", err
	}

	return posts, count, lastPostId, limit, nil
}

// RetrieveCountAndRecords retrieves the count of posts that match the criteria and the corresponding post records.
// It executes the provided count and data queries, processes the results, and returns the post count along with the post DTOs.
func retrieveCountAndRecords(ctx context.Context, tx pgx.Tx, countQuery string, countQueryArgs []interface{},
	dataQuery string, dataQueryArgs []interface{}) (int, []*schemas.PostDTO, *schemas.CustomError, int, error) {
	// Get the count of posts in the database that match the criteria
	row := tx.QueryRow(ctx, countQuery, countQueryArgs...)

	var count int
	if err := row.Scan(&count); err != nil {
		return 0, nil, schemas.DatabaseError, http.StatusInternalServerError, err
	}

	var rows pgx.Rows
	var err error

	rows, err = tx.Query(ctx, dataQuery, dataQueryArgs...)
	if err != nil {
		return 0, nil, schemas.DatabaseError, http.StatusInternalServerError, err
	}

	// Iterate over the rows and create the post DTOs
	posts := make([]*schemas.PostDTO, 0)

	for rows.Next() {
		post := &schemas.PostDTO{}
		var createdAt time.Time
		var longitude, latitude pgtype.Float8
		var accuracy pgtype.Int4

		if err := rows.Scan(&post.PostId, &post.Author.Username, &post.Author.Nickname, &post.Author.ProfilePictureURL,
			&post.Content, &createdAt, &longitude, &latitude, &accuracy); err != nil {
			return 0, nil, schemas.DatabaseError, http.StatusInternalServerError, err
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

		post.CreationDate = createdAt.Format(time.RFC3339)
		posts = append(posts, post)
	}

	return count, posts, nil, 0, nil
}

// parseLimitAndPostId parses the 'limit' and 'lastPostId' from the query parameters and provides default values if necessary.
func parseLimitAndPostId(limit, lastPostId string) (string, string) {
	intLimit, err := strconv.Atoi(limit)
	if err != nil || intLimit > 10 || intLimit < 1 {
		limit = "10"
	}

	postId, err := uuid.Parse(lastPostId)
	if err != nil || postId == uuid.Nil {
		lastPostId = ""
	}

	return limit, lastPostId
}
