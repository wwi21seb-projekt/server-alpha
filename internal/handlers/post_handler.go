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
var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

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

		repostedPost := psql.Select("content", "posts.created_at", "users.username", "users.nickname",
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
	insertQuery := psql.Insert("alpha_schema.posts").Columns("post_id", "author_id", "content", "created_at")

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

		queryString, args, _ := psql.Insert("alpha_schema.hashtags").Columns("hashtag_id", "content").
			Values(hashtagId, hashtag).Suffix("ON CONFLICT (content) DO UPDATE SET content=alpha_schema.hashtags.content " +
			"RETURNING hashtag_id").ToSql()
		if err := tx.QueryRow(ctx, queryString, args...).Scan(&hashtagId); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}

		queryString, args, _ = psql.Insert("alpha_schema.many_posts_has_many_hashtags").Columns("post_id_posts", "hashtag_id_hashtags").
			Values(postId, hashtagId).ToSql()
		if _, err = tx.Exec(ctx, queryString, args...); err != nil {
			utils.WriteAndLogError(ctx, goerrors.DatabaseError, http.StatusInternalServerError, err)
			return
		}
	}

	// Get the author
	queryString, args, _ := psql.Select("username", "nickname", "profile_picture_url").
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
	limitInt, _ := strconv.Atoi(limit)

	// Get the user ID from the JWT token
	claims := ctx.Value(utils.ClaimsKey.String()).(jwt.MapClaims)
	userId := claims["sub"].(string)

	// Build dataQueryString
	dataQueryBuilder := psql.Select().
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

	countQueryBuilder := psql.
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
	var userId string

	countQueryBuilder := psql.Select("COUNT(*)").From("alpha_schema.posts")
	dataQueryBuilder := psql.Select().
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
		var longitude, latitude, repostLongitude, repostLatitude pgtype.Float8
		var accuracy, repostAccuracy pgtype.Int4
		var repostContent, repostAuthorUsername, repostAuthorNickname, repostAuthorProfilePictureURL pgtype.Text
		var repostCreatedAt pgtype.Timestamptz

		if err := rows.Scan(&post.PostId, &post.Content, &createdAt, &longitude, &latitude, &accuracy,
			&post.Author.Username, &post.Author.Nickname, &post.Author.ProfilePictureURL,
			&repostContent, &repostCreatedAt, &repostLongitude, &repostLatitude, &repostAccuracy,
			&repostAuthorUsername, &repostAuthorNickname, &repostAuthorProfilePictureURL,
			&post.Likes, &post.Liked); err != nil {
			return 0, nil, goerrors.DatabaseError, http.StatusInternalServerError, err
		}

		if longitude.Valid && latitude.Valid && accuracy.Valid {
			post.Location = &schemas.LocationDTO{
				Longitude: longitude.Float64,
				Latitude:  latitude.Float64,
				Accuracy:  accuracy.Int32,
			}
		}

		if repostContent.Valid && repostCreatedAt.Valid && repostAuthorNickname.Valid &&
			repostAuthorProfilePictureURL.Valid && repostAuthorUsername.Valid {
			// Set the repost DTO
			post.Repost = &schemas.RepostDTO{
				Content:      repostContent.String,
				CreationDate: repostCreatedAt.Time.Format(time.RFC3339),
				Author: schemas.AuthorDTO{
					Username:          repostAuthorUsername.String,
					Nickname:          repostAuthorNickname.String,
					ProfilePictureURL: repostAuthorProfilePictureURL.String,
				},
			}

			if repostLongitude.Valid && repostLatitude.Valid && repostAccuracy.Valid {
				post.Repost.Location = &schemas.LocationDTO{
					Longitude: repostLongitude.Float64,
					Latitude:  repostLatitude.Float64,
					Accuracy:  repostAccuracy.Int32,
				}
			}
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
