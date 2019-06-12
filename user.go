package permission

import (
	"time"
)

// User is a simple representation of an authenticated user.
type User struct {
	Username   string
	ValidUntil int64
}

// NewUser creates a new User with the given name and cache time.
func NewUser(username string, cacheTime int64) *User {
	return &User{
		Username:   username,
		ValidUntil: time.Now().Unix() + cacheTime,
	}
}
