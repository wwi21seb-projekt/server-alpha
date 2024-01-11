package handlers

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"net/http"
	"regexp"
	"server-alpha/internal/managers"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"time"
)

type PostHdl interface {
	CreatePost(w http.ResponseWriter, r *http.Request)
}

type PostHandler struct {
	DatabaseManager managers.DatabaseMgr
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

	// Create the hashtags
	for _, hashtag := range hashtags {
		hashtagId := uuid.New()

		queryString = "INSERT INTO alpha_schema.hashtags (hashtag_id, content) VALUES($1, $2) ON CONFLICT DO NOTHING"
		if _, err = tx.Exec(transactionCtx, queryString, hashtagId, hashtag); err != nil {
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
		Content:   createPostRequest.Content,
		CreatedAt: createdAt.String(),
	}, http.StatusCreated)
}
