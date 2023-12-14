package schemas

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID          *uuid.UUID `json:"id"`
	Username    string     `json:"username"`
	Nickname    string     `json:"nickname"`
	Email       string     `json:"email"`
	Password    string     `json:"password"`
	CreatedAt   *time.Time `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type UserToken struct {
	ID        *uuid.UUID `json:"id"`
	UserID    *uuid.UUID `json:"user_id"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at"`
}
