package permission

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy"
)

const (
	permitUserIdentifier = "user"
)

// BasicBackend is a permission backend that uses HTTP Basic Authentication and static users and rules.
type BasicBackend struct {
	Users         map[string]string
	Permits       map[string]*Permit
	DefaultPermit *Permit
	PublicPermit  *Permit
}

// GetUsername authenticates and returns a username, if successful.
func (backend *BasicBackend) GetUsername(r *http.Request) (username string, authSuccess bool, err error) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Basic ")
	username, ok := backend.Users[token]
	if ok {
		return username, true, nil
	}
	return "", false, nil
}

// GetPermit returns the user permit of a user.
func (backend *BasicBackend) GetPermit(username string) (*Permit, error) {
	permit, ok := backend.Permits[username]
	if ok {
		return permit, nil
	}
	return nil, nil
}

// GetDefaultPermit returns the default permit.
func (backend *BasicBackend) GetDefaultPermit() (*Permit, error) {
	return backend.DefaultPermit, nil
}

// GetPublicPermit returns the public permit.
func (backend *BasicBackend) GetPublicPermit() (*Permit, error) {
	return backend.PublicPermit, nil
}

// Login returns "401 Authentication Required"
func (backend *BasicBackend) Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error) {
	if realm == "" {
		realm = "Restricted"
	}
	w.Header().Set("WWW-Authenticate", "Basic realm=\""+realm+"\"")
	return true, http.StatusUnauthorized, nil
}

// Name returns the name of the plug.
func (backend *BasicBackend) Name() string {
	return BackendBasicName
}

func init() {
	RegisterBackend(BackendBasicName, NewBasicBackend)
}

// NewBasicBackend creates a new BasicBackend.
func NewBasicBackend(c *caddy.Controller, now int64) (Backend, error) {

	new := BasicBackend{
		Users:   make(map[string]string),
		Permits: make(map[string]*Permit),
	}

	var nextPermit *Permit
	var username string
	var compiledPass string

	// we start right after the plugin keyword
	for c.NextBlock() {
		switch c.Val() {
		case permitUserIdentifier, DefaultIdentifier, PublicIdentifier:
			// save previous permit if exists
			if nextPermit != nil {
				nextPermit.Finalize()
				switch username {
				case DefaultIdentifier:
					new.DefaultPermit = nextPermit
				case PublicIdentifier:
					new.PublicPermit = nextPermit
				default:
					new.Permits[username] = nextPermit
					if compiledPass != "" {
						new.Users[compiledPass] = username
					}
				}
			}
			// create new permit
			nextPermit = NewPermit(0, now)
			switch c.Val() {
			// add username, compile password
			case permitUserIdentifier:
				args := c.RemainingArgs()
				switch len(args) {
				case 1:
					username = args[0]
					compiledPass = ""
				case 2:
					username = args[0]
					compiledPass = compileBasicAuthCreds(args[0], args[1])
				default:
					return nil, c.ArgErr()
				}
			case DefaultIdentifier:
				username = DefaultIdentifier
			case PublicIdentifier:
				username = PublicIdentifier
			}
		default:
			// add permission
			methods := c.Val()
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			err := nextPermit.AddRule(methods, c.Val())
			if err != nil {
				return nil, err
			}
		}
	}

	// save last permit if exists
	if nextPermit != nil {
		nextPermit.Finalize()
		switch username {
		case DefaultIdentifier:
			new.DefaultPermit = nextPermit
		case PublicIdentifier:
			new.PublicPermit = nextPermit
		default:
			new.Permits[username] = nextPermit
			if compiledPass != "" {
				new.Users[compiledPass] = username
			}
		}
	}

	return &new, nil

}

func compileBasicAuthCreds(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, password)))
}
