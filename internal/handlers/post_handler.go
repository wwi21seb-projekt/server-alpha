// Package handlers implements the handlers for the different routes of the server to handle the incoming HTTP requests.
package handlers

import (
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
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
	CreateLike(c *gin.Context)
	DeleteLike(c *gin.Context)
}

// PostHandler provides methods to handle post-related HTTP requests.
type PostHandler struct {
	DatabaseManager managers.DatabaseMgr
	JWTManager      managers.JWTMgr
}

var hashtagRegex = regexp.MustCompile(`#\w+`)
var errTransaction = errors.New("error beginning transaction")
var bearerPrefix = "Bearer "
var post_psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// NewPostHandler returns a new PostHandler with the provided managers and validator.
func NewPostHandler(databaseManager *managers.DatabaseMgr, jwtManager *managers.JWTMgr) PostHdl {
	return &PostHandler{
		DatabaseManager: *databaseManager,
		JWTManager:      *jwtManager,
	}
}

func (handler *PostHandler) CreatePost(ctx *gin.Context) {
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, errTransaction)
		return
	}
	var err error
	defer utils.RollbackTransaction(ctx, tx, err)

	createPostRequest := ctx.Value(utils.SanitizedPayloadKey.String()).(*schemas.CreatePostRequest)
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)
	userId := claims["sub"].(string)
	postDto := &schemas.PostDTO{}
	repostPostId := uuid.Nil

	// Check if this is a repost
	if createPostRequest.RepostedPostId != "" {
		postDto.Repost = &schemas.RepostDTO{}
		postDto.Repost.Author = schemas.AuthorDTO{}

		var longitute, latitude pgtype.Float8
		var accuracy pgtype.Int4
		var createdAt pgtype.Timestamptz

		repostedPost := post_psql.Select("content", "posts.created_at", "users.username", "users.nickname",
			"users.profile_picture_url", "longitude", "latitude", "accuracy", "repost_post_id").
			From("alpha_schema.posts").
			InnerJoin("alpha_schema.users ON author_id = user_id").
			Where("post_id = ?", createPostRequest.RepostedPostId)
		sql, args, _ := repostedPost.ToSql()

		row := tx.QueryRow(ctx, sql, args...)
		err := row.Scan(&postDto.Repost.Content, &createdAt, &postDto.Repost.Author.Username,
			&postDto.Repost.Author.Nickname, &postDto.Repost.Author.ProfilePictureURL, &longitute, &latitude, &accuracy, &repostPostId)
		// Check for general errors and specific RowNotFound error, which indicates that the post was not found
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				utils.WriteAndLogError(ctx, goerrors.PostNotFound, http.StatusNotFound, errors.New("post not found"))
				return
			}

			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		// If the post is a repost of a repost, we deny the request
		if repostPostId != uuid.Nil {
			utils.WriteAndLogError(ctx, goerrors.BadRequest, http.StatusBadRequest, errors.New("repost of repost"))
			return
		}

		// Set the location if it exists
		if longitute.Valid && latitude.Valid && accuracy.Valid {
			postDto.Repost.Location = &schemas.LocationDTO{}
			postDto.Repost.Location.Longitude = longitute.Float64
			postDto.Repost.Location.Latitude = latitude.Float64
			postDto.Repost.Location.Accuracy = accuracy.Int32
		}

		// Set the creation date in the correct format
		postDto.Repost.CreationDate = createdAt.Time.Format(time.RFC3339)
	}

	// Create the post
	postId := uuid.New()
	createdAt := time.Now()
	arguments := []interface{}{postId, userId, createPostRequest.Content, createdAt}
	insertQuery := post_psql.Insert("alpha_schema.posts").Columns("post_id", "author_id", "content", "created_at")

	if createPostRequest.Location != (schemas.LocationDTO{}) {
		insertQuery = insertQuery.Columns("longitude", "latitude", "accuracy")
		arguments = append(arguments, createPostRequest.Location.Longitude, createPostRequest.Location.Latitude,
			createPostRequest.Location.Accuracy)
	}
	if postDto.Repost != nil {
		insertQuery = insertQuery.Columns("repost_post_id")
		arguments = append(arguments, createPostRequest.RepostedPostId)
	}

	insertQuery = insertQuery.Values(arguments...)
	sql, args, _ := insertQuery.ToSql()
	_, err = tx.Exec(ctx, sql, args...)
	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Get the hashtags
	hashtags := hashtagRegex.FindAllString(createPostRequest.Content, -1)
	for _, hashtag := range hashtags {
		hashtagId := uuid.New()

		queryString, args, _ := post_psql.Insert("alpha_schema.hashtags").Columns("hashtag_id", "content").
			Values(hashtagId, hashtag).Suffix("ON CONFLICT (content) DO UPDATE SET content=alpha_schema.hashtags.content " +
			"RETURNING hashtag_id").ToSql()
		if err := tx.QueryRow(ctx, queryString, args...).Scan(&hashtagId); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		queryString, args, _ = post_psql.Insert("alpha_schema.many_posts_has_many_hashtags").Columns("post_id_posts", "hashtag_id_hashtags").
			Values(postId, hashtagId).ToSql()
		if _, err = tx.Exec(ctx, queryString, args...); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	// Get the author
	queryString, args, _ := post_psql.Select("username", "nickname", "profile_picture_url").
		From("alpha_schema.users").Where("user_id = ?", userId).ToSql()
	row := tx.QueryRow(ctx, queryString, args...)

	author := &schemas.AuthorDTO{}
	if err := row.Scan(&author.Username, &author.Nickname, &author.ProfilePictureURL); err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	// Commit the transaction
	if err := utils.CommitTransaction(ctx, tx); err != nil {
		return
	}

	// Create the post DTO
	post := &schemas.PostDTO{
		PostId:       postId.String(),
		Author:       *author,
		Content:      createPostRequest.Content,
		CreationDate: createdAt.Format(time.RFC3339),
		Likes:        0,
		Liked:        false,
		Repost:       postDto.Repost,
	}

	if createPostRequest.Location != (schemas.LocationDTO{}) {
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
	userId := claims["sub"].(string)

	// Check if the user is the author of the post
	queryString := "SELECT author_id, content FROM alpha_schema.posts WHERE post_id = $1"
	row := tx.QueryRow(ctx, queryString, postId)

	var authorId, content string
	if err := row.Scan(&authorId, &content); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteAndLogError(ctx, goerrors.PostNotFound, http.StatusNotFound, err)
			return
		}

		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

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
	// Get the query parameters
	q := ctx.Query(utils.QueryParamKey)
	limit, lastPostId := utils.ParseLimitAndPostId(ctx.Query(utils.LimitParamKey), ctx.Query(utils.PostIdParamKey))
	limitInt, _ := strconv.Atoi(limit)

	// Get the user ID from the JWT token
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)
	userId := claims["sub"].(string)

	// Build dataQueryString
	dataQueryBuilder := post_psql.Select().
		Columns("posts.post_id", "posts.content", "posts.created_at", "posts.longitude", "posts.latitude", "posts.accuracy").
		Columns("users.username", "users.nickname", "users.profile_picture_url").
		Columns("repost.content", "repost.created_at", "repost.longitude", "repost.latitude", "repost.accuracy").
		Columns("repost_author.username", "repost_author.nickname", "repost_author.profile_picture_url").
		Column("COUNT(likes.post_id) AS likes").
		Column("CASE WHEN EXISTS (SELECT 1 FROM alpha_schema.likes WHERE likes.user_id = ? AND likes.post_id = posts.post_id) THEN TRUE ELSE FALSE END AS liked", userId).
		From("alpha_schema.posts").
		InnerJoin("alpha_schema.users ON posts.author_id = user_id").
		InnerJoin("alpha_schema.many_posts_has_many_hashtags ON posts.post_id = post_id_posts").
		InnerJoin("alpha_schema.hashtags ON hashtag_id = hashtag_id_hashtags").
		LeftJoin("alpha_schema.likes ON posts.post_id = likes.post_id").
		LeftJoin("alpha_schema.posts AS repost ON posts.repost_post_id = repost.post_id").
		LeftJoin("alpha_schema.users AS repost_author ON repost.author_id = repost_author.user_id").
		Where("hashtags.content LIKE ?", "%"+q+"%")

	if lastPostId != "" {
		dataQueryBuilder = dataQueryBuilder.Where("posts.created_at < (SELECT created_at FROM alpha_schema.posts WHERE post_id = ?)", lastPostId)
	}

	dataQueryBuilder = dataQueryBuilder.
		GroupBy("posts.post_id", "users.username", "users.nickname", "users.profile_picture_url", "repost.content", "repost.created_at",
			"repost.longitude", "repost.latitude", "repost.accuracy", "repost_author.username", "repost_author.nickname", "repost_author.profile_picture_url").
		OrderBy("posts.created_at DESC").Limit(uint64(limitInt))

	countQueryBuilder := post_psql.
		Select("COUNT(DISTINCT posts.post_id)").
		From("alpha_schema.posts").
		InnerJoin("alpha_schema.users ON author_id = user_id").
		InnerJoin("alpha_schema.many_posts_has_many_hashtags ON posts.post_id = post_id_posts").
		InnerJoin("alpha_schema.hashtags ON hashtag_id = hashtag_id_hashtags").
		Where("hashtags.content LIKE ?", "%"+q+"%")

	dataQueryString, dataQueryArgs, _ := dataQueryBuilder.ToSql()
	countQueryString, countQueryArgs, _ := countQueryBuilder.ToSql()

	log.Println(dataQueryString)

	// Get count and posts
	count, posts, customErr, statusCode, err := handler.retrieveCountAndRecords(ctx, countQueryString, countQueryArgs,
		dataQueryString, dataQueryArgs)
	if err != nil {
		utils.WriteAndLogError(ctx, customErr, statusCode, err)
		return
	}

	// Create paginated response and send it
	paginatedResponse := createPaginatedResponse(posts, lastPostId, limit, count)
	utils.WriteAndLogResponse(ctx, paginatedResponse, http.StatusOK)
}

// HandleGetFeedRequest handles requests to retrieve a feed. It determines the feed type (public or private),
// retrieves the appropriate feed based on the user's subscriptions if needed, and creates a paginated response.
func (handler *PostHandler) HandleGetFeedRequest(ctx *gin.Context) {
	// Determine the feed type
	publicFeedWanted, claims, err := determineFeedType(ctx, handler)
	if err != nil {
		return
	}

	// Retrieve the feed based on the wanted feed type
	posts, records, lastPostId, limit, err := handler.retrieveFeed(ctx, publicFeedWanted, claims)
	if err != nil {
		return
	}

	paginatedResponse := createPaginatedResponse(posts, lastPostId, limit, records)
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
		// If no JWT token is provided, we assume the user wants the global feed
		return true, nil, nil
	}

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

	return publicFeedWanted, claims, nil
}

// RetrieveFeed retrieves the appropriate feed based on whether a public or private feed is requested.
// It builds the database query dynamically based on the feed type and user input, retrieves the posts,
// and returns the posts along with pagination details.
func (handler *PostHandler) retrieveFeed(ctx *gin.Context, publicFeedWanted bool,
	claims jwt.Claims) ([]*schemas.PostDTO, int, string, string, error) {
	limit, lastPostId := utils.ParseLimitAndPostId(ctx.Query(utils.LimitParamKey), ctx.Query(utils.PostIdParamKey))
	var userId string

	countQueryBuilder := post_psql.Select("COUNT(*)").From("alpha_schema.posts")
	dataQueryBuilder := post_psql.Select().
		Columns("posts.post_id", "posts.content", "posts.created_at", "posts.longitude", "posts.latitude", "posts.accuracy").
		Columns("users.username", "users.nickname", "users.profile_picture_url").
		Columns("repost.content", "repost.created_at", "repost.longitude", "repost.latitude", "repost.accuracy").
		Columns("repost_author.username", "repost_author.nickname", "repost_author.profile_picture_url").
		Column("COUNT(likes.post_id) AS likes")

	// Dynamically build queries based on user input
	if !publicFeedWanted {
		userId = claims.(jwt.MapClaims)["sub"].(string)
		countQueryBuilder = countQueryBuilder.
			InnerJoin("alpha_schema.subscriptions ON posts.author_id = subscriptions.subscribee_id").
			InnerJoin("alpha_schema.users ON posts.author_id = users.user_id").
			Where("subscriptions.subscriber_id = ?", userId)
		dataQueryBuilder = dataQueryBuilder.
			Column("CASE WHEN EXISTS (SELECT 1 FROM alpha_schema.likes WHERE likes.user_id = ? "+
				"AND likes.post_id = posts.post_id) THEN TRUE ELSE FALSE END AS liked", userId).
			From("alpha_schema.posts").
			InnerJoin("alpha_schema.subscriptions ON posts.author_id = subscriptions.subscribee_id").
			InnerJoin("alpha_schema.users ON posts.author_id = users.user_id").
			LeftJoin("alpha_schema.likes ON posts.post_id = likes.post_id").
			LeftJoin("alpha_schema.posts AS repost ON posts.repost_post_id = repost.post_id").
			LeftJoin("alpha_schema.users AS repost_author ON repost.author_id = repost_author.user_id").
			Where("subscriptions.subscriber_id = ?", userId)
	} else {
		dataQueryBuilder = dataQueryBuilder.
			Column("FALSE AS liked").
			From("alpha_schema.posts").
			InnerJoin("alpha_schema.users ON posts.author_id = users.user_id").
			LeftJoin("alpha_schema.likes ON posts.post_id = likes.post_id").
			LeftJoin("alpha_schema.posts AS repost ON posts.repost_post_id = repost.post_id").
			LeftJoin("alpha_schema.users AS repost_author ON repost.author_id = repost_author.user_id")
	}

	// Append additional clauses to the data query based on the lastPostId
	if lastPostId != "" {
		// If we don't have a last post ID, we'll return the newest posts
		dataQueryBuilder = dataQueryBuilder.Where("posts.created_at < (SELECT created_at FROM alpha_schema.posts WHERE post_id = ?)", lastPostId)
	}

	intLimit, _ := strconv.Atoi(limit)
	dataQueryBuilder = dataQueryBuilder.
		GroupBy("posts.post_id", "users.username", "users.nickname", "users.profile_picture_url", "repost.content", "repost.created_at",
			"repost.longitude", "repost.latitude", "repost.accuracy", "repost_author.username", "repost_author.nickname", "repost_author.profile_picture_url").
		OrderBy("posts.created_at DESC").Limit(uint64(intLimit))

	dataQuery, dataQueryArgs, _ := dataQueryBuilder.ToSql()
	countQuery, countQueryArgs, _ := countQueryBuilder.ToSql()

	count, posts, customErr, statusCode, err := handler.retrieveCountAndRecords(ctx, countQuery, countQueryArgs, dataQuery, dataQueryArgs)
	if err != nil {
		utils.WriteAndLogError(ctx, customErr, statusCode, err)
		return nil, 0, "", "", err
	}

	return posts, count, lastPostId, limit, nil
}

// RetrieveCountAndRecords retrieves the count of posts that match the criteria and the corresponding post records.
// It executes the provided count and data queries, processes the results, and returns the post count along with the post DTOs.
func (handler *PostHandler) retrieveCountAndRecords(ctx *gin.Context, countQuery string, countQueryArgs []interface{},
	dataQuery string, dataQueryArgs []interface{}) (int, []*schemas.PostDTO, *goerrors.CustomError, int, error) {
	// Get the count of posts in the database that match the criteria
	row := handler.DatabaseManager.GetPool().QueryRow(ctx, countQuery, countQueryArgs...)

	var count int
	if err := row.Scan(&count); err != nil {
		return 0, nil, goerrors.DatabaseError, http.StatusInternalServerError, err
	}

	var rows pgx.Rows
	var err error

	rows, err = handler.DatabaseManager.GetPool().Query(ctx, dataQuery, dataQueryArgs...)
	if err != nil {
		return 0, nil, goerrors.DatabaseError, http.StatusInternalServerError, err
	}

	// Iterate over the rows and create the post DTOs
	posts, err := utils.CreatePostDtoFromRows(rows)
	if err != nil {
		return 0, nil, goerrors.DatabaseError, http.StatusInternalServerError, err
	}

	return count, posts, nil, 0, nil
}

func (handler *PostHandler) CreateLike(ctx *gin.Context) {
	var err error
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, errTransaction)
		return
	}
	defer utils.RollbackTransaction(ctx, tx, err)

	// Get the post ID from the URL
	postId := ctx.Param(utils.PostIdParamKey)
	if _, err := uuid.Parse(postId); err != nil {
		utils.WriteAndLogError(ctx, goerrors.PostNotFound, http.StatusBadRequest, err)
		return
	}

	// Get the user ID from the JWT token
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)
	userId := claims["sub"].(string)

	queryString := `INSERT INTO alpha_schema.likes (user_id, post_id, liked_at) VALUES($1,$2,$3)
					ON CONFLICT (user_id, post_id) DO NOTHING;`

	result, err := tx.Exec(ctx, queryString, userId, postId, time.Now())
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgerrcode.IsIntegrityConstraintViolation(pgErr.Code) {
		utils.WriteAndLogError(ctx, goerrors.PostNotFound, http.StatusNotFound, err)
		return
	}

	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}

	if result.RowsAffected() == 0 {
		utils.WriteAndLogResponse(ctx, goerrors.AlreadyLiked, http.StatusConflict)
		return
	}
	// Commit the transaction
	if err := utils.CommitTransaction(ctx, tx); err != nil {
		return
	}

	utils.WriteAndLogResponse(ctx, nil, http.StatusNoContent)
}

func (handler *PostHandler) DeleteLike(ctx *gin.Context) {
	var err error
	tx := utils.BeginTransaction(ctx, handler.DatabaseManager.GetPool())
	if tx == nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, errTransaction)
		return
	}
	defer utils.RollbackTransaction(ctx, tx, err)

	// Get the post ID from the URL
	postId := ctx.Param(utils.PostIdParamKey)
	// Get the user ID from the JWT token
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)
	userId := claims["sub"].(string)

	queryString := `SELECT EXISTS(SELECT 1 FROM alpha_schema.posts WHERE post_id = $1) AS post_exists, 
                       EXISTS(SELECT 1 FROM alpha_schema.likes WHERE post_id = $1 AND user_id = $2) AS like_exists;`

	var postExists, likeExists bool
	err = tx.QueryRow(ctx, queryString, postId, userId).Scan(&postExists, &likeExists)
	if err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}
	if !postExists {
		utils.WriteAndLogResponse(ctx, goerrors.PostNotFound, http.StatusNotFound)
		return
	}
	if !likeExists {
		utils.WriteAndLogResponse(ctx, goerrors.NotLiked, http.StatusConflict)
		return
	}
	queryString = `DELETE FROM alpha_schema.likes WHERE post_id = $1 AND user_id = $2`
	if _, err = tx.Exec(ctx, queryString, postId, userId); err != nil {
		utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
		return
	}
	// Commit the transaction
	if err := utils.CommitTransaction(ctx, tx); err != nil {
		return
	}

	utils.WriteAndLogResponse(ctx, nil, http.StatusNoContent)
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
