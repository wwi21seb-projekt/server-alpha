package schemas

// ErrorDTO is a struct that represents an error response
// Error is the custom error, see CustomError
type ErrorDTO struct {
	Error CustomError `json:"error"`
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

// TokenDTO is a struct that represents a token response
// Token is the JWT token
type TokenDTO struct {
	Token string `json:"token"`
}

// AuthorDTO is a struct that represents an author response
// Username is the username of the author
// Nickname is the nickname of the author
// ProfilePictureURL is the profile picture URL of the author
type AuthorDTO struct {
	Username          string `json:"username"`
	Nickname          string `json:"nickname"`
	ProfilePictureURL string `json:"profile_picture_url"`
}

// PostDTO is a struct that represents a post response
// PostId is the ID of the post
// AuthorId is the ID of the author
// Content is the content of the post
// CreatedAt is the timestamp of when the post was created
type PostDTO struct {
	PostId    string    `json:"post_id"`
	Author    AuthorDTO `json:"author"`
	Content   string    `json:"content"`
	CreatedAt string    `json:"created_at"`
}

/** Request Objects **/

// RegistrationRequest is a struct that represents a registration request
// Username is required and must be less than 20 characters
// Nickname is optional and must be less than 25 characters
// Email is required and must be a valid email
// Password is required and must be at least 8 characters
type RegistrationRequest struct {
	Username string `json:"username" validate:"required,max=20,username_validation"`
	Nickname string `json:"nickname" validate:"max=25"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,password_validation"`
}

// ActivationRequest is a struct that represents an activation request
// Token is required and must be a 6-digit number
type ActivationRequest struct {
	Token string `json:"token" validate:"required,numeric,len=6"`
}

// LoginRequest is a struct that represents a login request
// Username is required and must be less than 20 characters
// Password is required and must be at least 8 characters
type LoginRequest struct {
	Username string `json:"username" validate:"required,max=20,username_validation"`
	Password string `json:"password" validate:"required,min=8,password_validation"`
}

// CreatePostRequest is a struct that represents a create post request
// Content is required and must be less than 256 characters, as well as written in UTF-8
type CreatePostRequest struct {
	Content string `json:"content" validate:"required,max=256,post_validation"`
}
