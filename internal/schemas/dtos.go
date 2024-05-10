package schemas

import "github.com/google/uuid"

// ErrorDTO is a struct that represents an error response
// Error is the custom error, see CustomError
type ErrorDTO struct {
	Error CustomError `json:"error"`
}

// ImprintDTO is a struct that represents an imprint response
// Text is the imprint text
type ImprintDTO struct {
	Text string `json:"text"`
}

// UserDTO is a struct that represents a user response
// Username is the username of the user
// Nickname is the nickname of the user
// Email is the email of the user
type UserDTO struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
}

// UserNicknameAndStatusDTO is a struct that represents a user response with nickname and status
// Nickname is the nickname of the user
// Status is the status of the user
type UserNicknameAndStatusDTO struct {
	Nickname string `json:"nickname"`
	Status   string `json:"status"`
}

// TokenPairDTO is a struct that represents a token response
// Token is the main JWT token used for auth
// RefreshToken is the refresh token used to get a new token
type TokenPairDTO struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

// AuthorDTO is a struct that represents an author response
// Username is the username of the author
// Nickname is the nickname of the author
// ProfilePictureURL is the profile picture URL of the author
type AuthorDTO struct {
	Username          string `json:"username"`
	Nickname          string `json:"nickname"`
	ProfilePictureURL string `json:"profilePictureURL"`
}

// PostDTO is a struct that represents a post response
// PostId is the ID of the post
// AuthorId is the ID of the author
// Content is the content of the post
// CreatedAt is the timestamp of when the post was created
type PostDTO struct {
	PostId       string       `json:"postId"`
	Author       AuthorDTO    `json:"author"`
	CreationDate string       `json:"creationDate"`
	Content      string       `json:"content"`
	Location     *LocationDTO `json:"location,omitempty"`
}

// SubscriptionDTO is a struct that represents a subscription response
type SubscriptionDTO struct {
	SubscriptionId   uuid.UUID `json:"subscriptionId"`
	SubscriptionDate string    `json:"subscriptionDate"`
	Following        string    `json:"following"`
	Follower         string    `json:"follower"`
}

// SubscriptionUserDTO is a struct that represents a subscription response
type SubscriptionUserDTO struct {
	FollowerId        *string `json:"followerId"`
	FollowingId       *string `json:"followingId"`
	Username          string  `json:"username"`
	Nickname          string  `json:"nickname"`
	ProfilePictureUrl string  `json:"profilePictureUrl"`
}

// LocationDTO is a struct that represents a location response
// Longitude is the longitude of the location
// Latitude is the latitude of the location
// Accuracy is the accuracy of the location in meters
type LocationDTO struct {
	Longitude float64 `json:"longitude"`
	Latitude  float64 `json:"latitude"`
	Accuracy  int32   `json:"accuracy"`
}

// PaginatedResponse is a struct that represents a paginated response
// Records is the records of the response
// Pagination is the pagination of the response
type PaginatedResponse struct {
	Records    interface{} `json:"records"`
	Pagination interface{} `json:"pagination"`
}

// PostPagination is a struct that represents a post pagination
// LastPostId is the last post ID of the pagination
// Limit is the given limit of the pagination
// Records is the total records of the pagination
type PostPagination struct {
	LastPostId string `json:"lastPostId"`
	Limit      string `json:"limit"`
	Records    int    `json:"records"`
}

// Pagination is a struct that represents a pagination
// Offset is the given offset of the pagination
// Limit is the given limit of the pagination
// Records is the total records of the pagination
type Pagination struct {
	Offset  int `json:"offset"`
	Limit   int `json:"limit"`
	Records int `json:"records"`
}

// UserProfileDTO is a struct that represents a user profile response
// Username is the username of the user
// Nickname is the nickname of the user
// Status is the status of the user
// ProfilePicture is the profile picture URL of the user
// Follower is the number of followers of the user
// Following is the number of users the user is following
// Posts is the number of posts of the user
// SubscriptionId is given if the user is followed by the authenticated user
type UserProfileDTO struct {
	Username       string     `json:"username"`
	Nickname       string     `json:"nickname"`
	Status         string     `json:"status"`
	ProfilePicture string     `json:"profilePicture"`
	Follower       int        `json:"follower"`
	Following      int        `json:"following"`
	Posts          int        `json:"posts"`
	SubscriptionId *uuid.UUID `json:"subscriptionId"`
}

type MetadataDTO struct {
	ApiVersion  string `json:"apiVersion"`
	ApiName     string `json:"apiName"`
	PullRequest string `json:"pullRequest,omitempty"`
}
