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
	Token string `json:"token" validate:"required,numeric,eq=6"`
}

// LoginRequest is a struct that represents a login request
// Username is required and must be less than 20 characters
// Password is required and must be at least 8 characters
type LoginRequest struct {
	Username string `json:"username" validate:"required,max=20,username_validation"`
	Password string `json:"password" validate:"required,min=8,password_validation"`
}
