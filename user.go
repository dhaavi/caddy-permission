package authplugger

import (
	"time"
)

type User struct {
	Username   string
	ValidUntil int64
}

func NewUser(username string, cacheTime int64) *User {
	return &User{
		Username:   username,
		ValidUntil: time.Now().Unix() + cacheTime,
	}
}
