// Package handlers implements the handlers for the different routes of the server to handle the incoming HTTP requests.
package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wwi21seb-projekt/errors-go/goerrors"
	"github.com/wwi21seb-projekt/server-alpha/internal/managers"
	"github.com/wwi21seb-projekt/server-alpha/internal/schemas"
	"github.com/wwi21seb-projekt/server-alpha/internal/utils"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// PostHdl defines the interface for handling post-related HTTP requests.
type PostHdl interface {
	CreatePost(c *gin.Context)
	DeletePost(c *gin.Context)
	QueryPosts(c *gin.Context)
	HandleGetFeedRequest(c *gin.Context)
	CreateComment(c *gin.Context)
	GetComments(c *gin.Context)
}

// PostHandler provides methods to handle post-related HTTP requests.
type PostHandler struct {
	DatabaseManager managers.DatabaseMgr
	JWTManager      managers.JWTMgr
}

var hashtagRegex = regexp.MustCompile(`#\w+`)
var errTransaction = errors.New("error beginning transaction")
var bearerPrefix = "Bearer "

// NewPostHandler returns a new PostHandler with the provided managers and validator.
func NewPostHandler(databaseManager *managers.DatabaseMgr, jwtManager *managers.JWTMgr) PostHdl {
	return &PostHandler{
		DatabaseManager: *databaseManager,
		JWTManager:      *jwtManager,
	}
}

// CreatePost handles the creation of a new post. It begins a new transaction, validates the request payload,
// extracts the user ID from JWT token, inserts the post data into the database, handles hashtags,
// and commits the transaction.
func (handler *PostHandler) CreatePost(ctx *gin.Context) {
	// Begin a new transaction
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, errTransaction)
		return
	}
	var err error
	defer utils.RollbackTransaction(ctx, tx, err)

	// Fetch JWT and Payload from context
	createPostRequest := ctx.Value(utils.SanitizedPayloadKey.String()).(*schemas.CreatePostRequest)
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)

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

	_, err = tx.Exec(ctx, queryString, queryArgs...)
	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the hashtags
	hashtags := hashtagRegex.FindAllString(createPostRequest.Content, -1)

	for _, hashtag := range hashtags {
		hashtagId := uuid.New()

		queryString := `INSERT INTO alpha_schema.hashtags (hashtag_id, content) VALUES($1, $2) 
						ON CONFLICT (content) DO UPDATE SET content=alpha_schema.hashtags.content 
						RETURNING hashtag_id`
		if err := tx.QueryRow(ctx, queryString, hashtagId, hashtag).Scan(&hashtagId); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		queryString = "INSERT INTO alpha_schema.many_posts_has_many_hashtags (post_id_posts, hashtag_id_hashtags) VALUES($1, $2)"
		if _, err = tx.Exec(ctx, queryString, postId, hashtagId); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	// Get the author
	queryString = "SELECT username, nickname FROM alpha_schema.users WHERE user_id = $1"
	row := tx.QueryRow(ctx, queryString, userId)

	author := &schemas.AuthorDTO{}
	if err := row.Scan(&author.Username, &author.Nickname); err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(ctx, tx); err != nil {
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
	utils.WriteAndLogResponse(ctx, post, http.StatusCreated)
}

// DeletePost handles the deletion of a post by ID. It verifies the user's authorization to delete the post,
// deletes the post and its associated hashtags if they are no longer used, and commits the transaction.
func (handler *PostHandler) DeletePost(ctx *gin.Context) {
	// Begin a new transaction
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, errTransaction)
		return
	}
	var err error
	defer utils.RollbackTransaction(ctx, tx, err)

	// Get the post ID from the URL
	postId := ctx.Param(utils.PostIdParamKey)
	// Get the user ID from the JWT token
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)

	// Check if the user is the author of the post
	queryString := "SELECT author_id, content FROM alpha_schema.posts WHERE post_id = $1"
	row := tx.QueryRow(ctx, queryString, postId)

	var authorId string
	var content string
	if err := row.Scan(&authorId, &content); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(ctx, goerrors.PostNotFound, http.StatusNotFound, err)
			return
		}

		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	userId := claims["sub"].(string)
	if userId != authorId {
		utils.WriteAndLogError(ctx, goerrors.DeletePostForbidden, http.StatusForbidden,
			errors.New("user is not the author of the post"))
		return
	}

	// Delete the post
	queryString = "DELETE FROM alpha_schema.posts WHERE post_id = $1"
	if _, err = tx.Exec(ctx, queryString, postId); err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
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
		if _, err = tx.Exec(ctx, queryString, hashtag); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	// Commit the transaction
	if err := utils.CommitTransaction(ctx, tx); err != nil {
		return
	}

	// Write the response
	utils.WriteAndLogResponse(ctx, nil, http.StatusNoContent)
}

// QueryPosts handles querying of posts based on the provided query parameters. It builds the database query dynamically,
// retrieves the count and records of matching posts, and creates a paginated response.
func (handler *PostHandler) QueryPosts(ctx *gin.Context) {
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, errTransaction)
		return
	}
	var err error
	defer utils.RollbackTransaction(ctx, tx, err)

	// Get the query parameters
	q := ctx.Query(utils.QueryParamKey)
	limit, lastPostId := parseLimitAndPostId(ctx.Query(utils.LimitParamKey), ctx.Query(utils.PostIdParamKey))

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
	count, posts, customErr, statusCode, err := retrieveCountAndRecords(ctx, tx, countQueryString, countQueryArgs,
		dataQueryString, dataQueryArgs)
	if err != nil {
		utils.WriteAndLogError(ctx, customErr, statusCode, err)
		return
	}

	// Create paginated response and send it
	paginatedResponse := createPaginatedResponse(posts, lastPostId, limit, count)

	if err := utils.CommitTransaction(ctx, tx); err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
	}

	utils.WriteAndLogResponse(ctx, paginatedResponse, http.StatusOK)
}

// HandleGetFeedRequest handles requests to retrieve a feed. It determines the feed type (public or private),
// retrieves the appropriate feed based on the user's subscriptions if needed, and creates a paginated response.
func (handler *PostHandler) HandleGetFeedRequest(ctx *gin.Context) {
	// Begin a new transaction
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError,
			errTransaction)
		return
	}
	var err error
	defer utils.RollbackTransaction(ctx, tx, err)

	// Determine the feed type
	publicFeedWanted, claims, err := determineFeedType(ctx, handler)
	if err != nil {
		return
	}

	// Retrieve the feed based on the wanted feed type
	posts, records, lastPostId, limit, err := retrieveFeed(ctx, tx, publicFeedWanted, claims)
	if err != nil {
		return
	}

	paginatedResponse := createPaginatedResponse(posts, lastPostId, limit, records)

	if err := utils.CommitTransaction(ctx, tx); err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
	}

	utils.WriteAndLogResponse(ctx, paginatedResponse, http.StatusOK)
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
func determineFeedType(c *gin.Context, handler *PostHandler) (bool, jwt.Claims, error) {
	// Get UserId from JWT token
	authHeader := c.GetHeader("Authorization")
	var claims jwt.Claims
	var err error
	publicFeedWanted := false

	if authHeader == "" {
		publicFeedWanted = true
	} else {
		if !strings.HasPrefix(authHeader, bearerPrefix) || len(authHeader) <= len(bearerPrefix) {
			err = errors.New("invalid authorization header")
			utils.WriteAndLogError(c, goerrors.InvalidToken, http.StatusBadRequest, err)
			return false, nil, err
		}

		jwtToken := authHeader[len(bearerPrefix):]
		claims, err = handler.JWTManager.ValidateJWT(jwtToken)
		if err != nil {
			utils.WriteAndLogError(c, goerrors.Unauthorized, http.StatusUnauthorized, err)
			return false, nil, err
		}

		feedType := c.Query(utils.FeedTypeParamKey)
		if feedType == "global" {
			publicFeedWanted = true
		}
	}

	return publicFeedWanted, claims, nil
}

// RetrieveFeed retrieves the appropriate feed based on whether a public or private feed is requested.
// It builds the database query dynamically based on the feed type and user input, retrieves the posts,
// and returns the posts along with pagination details.
func retrieveFeed(ctx *gin.Context, tx pgx.Tx, publicFeedWanted bool,
	claims jwt.Claims) ([]*schemas.PostDTO, int, string, string, error) {
	limit, lastPostId := parseLimitAndPostId(ctx.Query(utils.LimitParamKey), ctx.Query(utils.PostIdParamKey))

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
		utils.WriteAndLogError(ctx, customErr, statusCode, err)
		return nil, 0, "", "", err
	}

	return posts, count, lastPostId, limit, nil
}

// RetrieveCountAndRecords retrieves the count of posts that match the criteria and the corresponding post records.
// It executes the provided count and data queries, processes the results, and returns the post count along with the post DTOs.
func retrieveCountAndRecords(ctx *gin.Context, tx pgx.Tx, countQuery string, countQueryArgs []interface{},
	dataQuery string, dataQueryArgs []interface{}) (int, []*schemas.PostDTO, *goerrors.CustomError, int, error) {
	// Get the count of posts in the database that match the criteria
	row := tx.QueryRow(ctx, countQuery, countQueryArgs...)

	var count int
	if err := row.Scan(&count); err != nil {
		return 0, nil, goerrors.DatabaseError, http.StatusInternalServerError, err
	}

	var rows pgx.Rows
	var err error

	rows, err = tx.Query(ctx, dataQuery, dataQueryArgs...)
	if err != nil {
		return 0, nil, goerrors.DatabaseError, http.StatusInternalServerError, err
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
			return 0, nil, goerrors.DatabaseError, http.StatusInternalServerError, err
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

func (handler *PostHandler) CreateComment(ctx *gin.Context) {
	// Begin a new transaction
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, errTransaction)
		return
	}
	var err error
	defer utils.RollbackTransaction(ctx, tx, err)

	// Fetch JWT and Payload from context
	createCommentRequest := ctx.Value(utils.SanitizedPayloadKey.String()).(*schemas.CreateCommentRequest)
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)

	// Create the comment
	commentId := uuid.New()
	userId := claims["sub"].(string)
	postId := ctx.Param(utils.PostIdParamKey)
	createdAt := time.Now()

	queryString := "INSERT INTO alpha_schema.comments (comment_id, post_id, author_id, created_at, content) VALUES($1, $2, $3, $4, $5)"
	queryArgs := []interface{}{commentId, postId, userId, createdAt, createCommentRequest.Content}

	_, err = tx.Exec(ctx, queryString, queryArgs...)
	if err != nil {
		// Checking if the error is due to post not found
		pgErr, ok := err.(*pgconn.PgError)
		if ok && pgErr.Code == pgerrcode.ForeignKeyViolation {
			// Handling the error for post not found
			utils.WriteAndLogError(ctx, goerrors.PostNotFound, http.StatusNotFound, errors.New("post not found"))
			return
		}
		// Handling other database errors
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the author
	queryString = "SELECT username, nickname, profile_picture_url FROM alpha_schema.users WHERE user_id = $1"
	row := tx.QueryRow(ctx, queryString, userId)

	author := &schemas.AuthorDTO{}
	if err := row.Scan(&author.Username, &author.Nickname, &author.ProfilePictureURL); err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(ctx, tx); err != nil {
		return
	}

	// Create the comment DTO
	comment := &schemas.CommentDTO{
		Content: createCommentRequest.Content,
		Author: schemas.AuthorDTO{
			Username:          author.Username,
			Nickname:          author.Nickname,
			ProfilePictureURL: author.ProfilePictureURL,
		},
	}

	// Write the response
	utils.WriteAndLogResponse(ctx, comment, http.StatusCreated)
}

// GetComments handles requests to get the comments to a post.
func (handler *PostHandler) GetComments(ctx *gin.Context) {
	// Extract postId from the URL parameter
	postId := ctx.Param(utils.PostIdParamKey)

	// Parse pagination parameters
	offset, limit, err := utils.ParsePaginationParams(ctx)
	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.BadRequest, http.StatusBadRequest, err)
		return
	}

	var postCount int
	queryString := "SELECT COUNT(*) FROM alpha_schema.posts WHERE post_id = $1"
	handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, postId).Scan(&postCount)
	if postCount == 0 {
		utils.WriteAndLogError(ctx, goerrors.PostNotFound, http.StatusNotFound, errors.New("post not found"))
		return
	}

	var commentCount int
	queryString = "SELECT COUNT(*) FROM alpha_schema.comments WHERE post_id = $1"
	handler.DatabaseManager.GetPool().QueryRow(ctx, queryString, postId).Scan(&commentCount)

	// Query to fetch comments related to the postId
	queryString = `
        SELECT c.comment_id, c.content, c.created_at, u.username, u.nickname
        FROM alpha_schema.comments AS c
        JOIN alpha_schema.users AS u ON c.author_id = u.user_id
        WHERE c.post_id = $1
        ORDER BY c.created_at DESC
        LIMIT $2 OFFSET $3`

	rows, err := handler.DatabaseManager.GetPool().Query(ctx, queryString, postId, limit, offset)
	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	comments := make([]schemas.CommentDTO, 0)
	for rows.Next() {
		var comment schemas.CommentDTO
		var author schemas.AuthorDTO

		var commentId string
		var createdAt time.Time

		if err := rows.Scan(&commentId, &comment.Content, &createdAt, &author.Username, &author.Nickname); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		comment.CommentId = commentId
		comment.Author = author
		comment.CreationDate = createdAt.Format(time.RFC3339)

		comments = append(comments, comment)
	}

	// Build and send the paginated response
	response := schemas.PaginatedResponse{
		Records: comments,
		Pagination: &schemas.Pagination{
			Offset:  offset,
			Limit:   limit,
			Records: commentCount,
		},
	}
	utils.WriteAndLogResponse(ctx, response, http.StatusOK)
}
