package authplugger

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/mholt/caddy"
)

type BasicAuthPlug struct {
	Users         map[string]string
	Permits       map[string]*Permit
	DefaultPermit *Permit
	PublicPermit  *Permit
}

func (plug *BasicAuthPlug) GetUsername(r *http.Request) (string, bool, error) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Basic ")
	username, ok := plug.Users[token]
	if ok {
		return username, true, nil
	}
	return "", false, nil
}

func (plug *BasicAuthPlug) GetPermit(username string) (*Permit, error) {
	permit, ok := plug.Permits[username]
	if ok {
		return permit, nil
	}
	return nil, nil
}

func (plug *BasicAuthPlug) GetDefaultPermit() (*Permit, error) {
	return plug.DefaultPermit, nil
}

func (plug *BasicAuthPlug) GetPublicPermit() (*Permit, error) {
	return plug.PublicPermit, nil
}

func (plug *BasicAuthPlug) Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error) {
	if realm == "" {
		realm = "Restricted"
	}
	w.Header().Set("WWW-Authenticate", "Basic realm=\""+realm+"\"")
	return true, http.StatusUnauthorized, nil
}

func (plug *BasicAuthPlug) Name() string {
	return "basic"
}

func init() {
	RegisterPlug("basic", NewBasicAuthPlug)
}

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
		case "user", "*", "!", "default", "public":
			// save previous permit if exists
			if nextPermit != nil {
				switch username {
				case "*":
					new.DefaultPermit = nextPermit
				case "!":
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
			case "user":
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
			case "*", "default":
				username = "*"
			case "!", "public":
				username = "!"
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
		switch username {
		case "*":
			new.DefaultPermit = nextPermit
		case "!":
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
