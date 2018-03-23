package authplugger

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/mholt/caddy"
)

const (
	permitUserIdentifier = "user"
)

// BasicAuthPlug is an Authplugger plug that uses HTTP Basic Authentication and static users and rules.
type BasicAuthPlug struct {
	Users         map[string]string
	Permits       map[string]*Permit
	DefaultPermit *Permit
	PublicPermit  *Permit
}

// GetUsername authenticates and returns a username, if successful.
func (plug *BasicAuthPlug) GetUsername(r *http.Request) (username string, authSuccess bool, err error) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Basic ")
	username, ok := plug.Users[token]
	if ok {
		return username, true, nil
	}
	return "", false, nil
}

// GetPermit returns the user permit of a user.
func (plug *BasicAuthPlug) GetPermit(username string) (*Permit, error) {
	permit, ok := plug.Permits[username]
	if ok {
		return permit, nil
	}
	return nil, nil
}

// GetDefaultPermit returns the default permit.
func (plug *BasicAuthPlug) GetDefaultPermit() (*Permit, error) {
	return plug.DefaultPermit, nil
}

// GetPublicPermit returns the public permit.
func (plug *BasicAuthPlug) GetPublicPermit() (*Permit, error) {
	return plug.PublicPermit, nil
}

// Login returns "401 Authentication Required"
func (plug *BasicAuthPlug) Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error) {
	if realm == "" {
		realm = "Restricted"
	}
	w.Header().Set("WWW-Authenticate", "Basic realm=\""+realm+"\"")
	return true, http.StatusUnauthorized, nil
}

// Name returns the name of the plug.
func (plug *BasicAuthPlug) Name() string {
	return BackendBasicName
}

func init() {
	RegisterPlug(BackendBasicName, NewBasicAuthPlug)
}

// NewBasicAuthPlug create a new BasicAuthPlug.
func NewBasicAuthPlug(c *caddy.Controller) (Plug, error) {

	new := BasicAuthPlug{
		Users:   make(map[string]string),
		Permits: make(map[string]*Permit),
	}

	var nextPermit *Permit
	var username string
	var compiledPass string

	// we start right after the plugin keyword
	for c.NextBlock() {
		switch c.Val() {
		case permitUserIdentifier, DefaultShort, DefaultLong, PublicShort, PublicLong:
			// save previous permit if exists
			if nextPermit != nil {
				nextPermit.Finalize()
				switch username {
				case DefaultShort, DefaultLong:
					new.DefaultPermit = nextPermit
				case PublicShort, PublicLong:
					new.PublicPermit = nextPermit
				default:
					new.Permits[username] = nextPermit
					if compiledPass != "" {
						new.Users[compiledPass] = username
					}
				}
			}
			// create new permit
			nextPermit = NewPermit(0)
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
			case DefaultShort, DefaultLong:
				username = DefaultShort
			case PublicShort, PublicLong:
				username = PublicShort
			}
		default:
			// add permission
			methods := c.Val()
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			err := nextPermit.AddPermission(methods, c.Val())
			if err != nil {
				return nil, err
			}
		}
	}

	// save last permit if exists
	if nextPermit != nil {
		nextPermit.Finalize()
		switch username {
		case DefaultShort, DefaultLong:
			new.DefaultPermit = nextPermit
		case PublicShort, PublicLong:
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
