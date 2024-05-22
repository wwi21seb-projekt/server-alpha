package utils

import (
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/wwi21seb-projekt/server-alpha/internal/schemas"
)

func CreatePostDtoFromRows(rows pgx.Rows) ([]*schemas.PostDTO, error) {
	var posts []*schemas.PostDTO

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
			return nil, err
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

	return posts, nil
}

// ParseLimitAndPostId parses the 'limit' and 'lastPostId' from the query parameters and provides default values if necessary.
func ParseLimitAndPostId(limit, lastPostId string) (string, string) {
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
