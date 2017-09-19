package authplugger

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/mholt/caddy"
)

type BasicAuthPlug struct {
	Permits       map[string]*Permit
	DefaultPermit *Permit
	PublicPermit  *Permit
}

func (plug *BasicAuthPlug) GetUserPermit(r *http.Request) (permit *Permit, authSuccess bool, err error) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Basic ")
	permit, ok := plug.Permits[token]
	if ok {
		return permit, true, nil
	}
	return nil, false, nil
}

func (plug *BasicAuthPlug) GetDefaultPermit() (*Permit, error) {
	return plug.DefaultPermit, nil
}

func (plug *BasicAuthPlug) GetPublicPermit() (*Permit, error) {
	return plug.PublicPermit, nil
}

func (plug *BasicAuthPlug) LoginResponder() LoginResponder {
	return BasicAuthenticate
}

func (plug *BasicAuthPlug) Name() string {
	return basicAuthPlugName()
}

func BasicAuthenticate(w http.ResponseWriter, r *http.Request, realm string) (int, error) {
	if realm == "" {
		realm = "Restricted"
	}
	w.Header().Set("WWW-Authenticate", "Basic realm=\""+realm+"\"")
	return http.StatusUnauthorized, nil
}

func init() {
	RegisterPlug("basicauth", NewBasicAuthPlug)
}

func NewBasicAuthPlug(c *caddy.Controller) (Plug, error) {

	new := BasicAuthPlug{
		Permits: make(map[string]*Permit),
	}

	var nextPermit *Permit
	var compiledPass string

	// we start right after the plugin keyword
	for c.NextBlock() {
		switch c.Val() {
		case "user", "*", "!":
			// save previous permit if exists
			if nextPermit != nil {
				switch nextPermit.Username {
				case "*":
					new.DefaultPermit = nextPermit
				case "!":
					new.PublicPermit = nextPermit
				default:
					new.Permits[compiledPass] = nextPermit
				}
			}
			// create new permit
			nextPermit = NewPermit(basicAuthPlugName)
			switch c.Val() {
			// add username, compile password
			case "user":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.ArgErr()
				}
				nextPermit.Username = args[0]
				compiledPass = compileBasicAuthCreds(args[0], args[1])
			case "*":
				nextPermit.Username = "*"
			case "!":
				nextPermit.Username = "!"
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
		switch nextPermit.Username {
		case "*":
			new.DefaultPermit = nextPermit
		case "!":
			new.PublicPermit = nextPermit
		default:
			new.Permits[compiledPass] = nextPermit
		}
	}

	return &new, nil

}

func basicAuthPlugName() string {
	return "basicauth"
}

func compileBasicAuthCreds(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, password)))
}
