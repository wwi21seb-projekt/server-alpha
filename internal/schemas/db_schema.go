// Package schemas defines the data structures
package schemas

import (
	"github.com/google/uuid"
	"time"
)

// User represents the data model for a user in the system.
type User struct {
	ID          *uuid.UUID `json:"id"`           // Unique identifier for the user.
	Username    string     `json:"username"`     // Username of the user.
	Nickname    string     `json:"nickname"`     // Nickname of the user.
	Email       string     `json:"email"`        // Email address of the user.
	Password    string     `json:"password"`     // Password hash of the user.
	CreatedAt   *time.Time `json:"created_at"`   // Timestamp when the user was created.
	ActivatedAt *time.Time `json:"activated_at"` // Timestamp when the user account was activated.
	ExpiresAt   *time.Time `json:"expires_at"`   // Timestamp when the user account expires.
}

// UserToken represents a token associated with a user, typically used for account activation or password reset.
type UserToken struct {
	ID        *uuid.UUID `json:"id"`         // Unique identifier for the user token.
	UserID    *uuid.UUID `json:"user_id"`    // Identifier of the user associated with this token.
	Token     string     `json:"token"`      // Token string.
	ExpiresAt *time.Time `json:"expires_at"` // Timestamp when the token expires.
}
