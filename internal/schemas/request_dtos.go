// Package schemas defines the request structures for various operations in the application.
package schemas

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
// Location is optional and must be a valid location if provided
type CreatePostRequest struct {
	Content  string      `json:"content" validate:"required,max=256,post_validation"`
	Location LocationDTO `json:"location" validate:"location_validation"`
}

// SubscriptionRequest is a struct that represents a Subscription request
// Following is required and must be less than 20 characters, since it is a username
type SubscriptionRequest struct {
	Following string `json:"following" validate:"required,max=20,username_validation"` // TODO: Lieber "username" als "following"
}

// ChangeTrivialInformationRequest is a struct that represents a NicknameChange request
// NewNickname is required and must be less than 25 characters
// Status is required and must be less than 256 characters
type ChangeTrivialInformationRequest struct {
	NewNickname string `json:"nickname" validate:"max=25"`
	Status      string `json:"status" validate:"max=256"`
}

// ChangePasswordRequest is a struct that represents a PasswordChange request
// OldPassword is required and must be at least 8 characters
// NewPassword is required and must be at least 8 characters
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" validate:"required,min=8,password_validation"`
	NewPassword string `json:"newPassword" validate:"required,min=8,password_validation"`
}

// RefreshTokenRequest is a struct that represents a RefreshToken request
// RefreshToken is required and must be a valid refresh token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

// CreateCommentRequest is a struct that represents a create comment request
// Content is required and must be less than 128 characters, as well as written in UTF-8
type CreateCommentRequest struct {
	Content string `json:"content" validate:"required,max=128,comment_validation"`
}
