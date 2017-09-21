package authplugger

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// AuthPlugger is an authentication plug middleware
type AuthPlugger struct {
	Next httpserver.Handler

	Plugs []Plug

	PublicPermit     *Permit
	PublicPermitLock sync.RWMutex
	PublicPermitTTL  int64

	ReadParentPath bool
	RemovePrefix   string
	Realm          string
}

// ServeHTTP implements the httpserver.Handler interface.
func (plugger *AuthPlugger) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	var username string
	var userSource string

	var authSuccess bool
	var err error

	// First get username
	for _, plug := range plugger.Plugs {

		username, authSuccess, err = plug.GetUsername(r)
		if err != nil {
			fmt.Printf("[authplugger] failed to get username from %s: %s", plug.Name(), err)
			username = ""
			continue
		}
		if !authSuccess {
			username = ""
			continue
		}

		// we got the username, now check permissions
		userSource = plug.Name()
		break

	}

	var allowed bool
	var plug Plug

	switch r.Method {
	// handle MOVE
	case "MOVE":
		allowed, plug = plugger.CheckPermits(username, "DELETE", r.RequestURI, false)
		if allowed {
			location := r.Header.Get("Location")
			if location != "" {
				allowed, plug = plugger.CheckPermits(username, "PUT", location, false)
			}
		}
	// handle COPY
	case "COPY":
		allowed, plug = plugger.CheckPermits(username, "GET", r.RequestURI, false)
		if allowed {
			location := r.Header.Get("Location")
			if location != "" {
				allowed, plug = plugger.CheckPermits(username, "PUT", location, false)
			}
		}
	default:
		// handle websocket upgrades
		if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
			allowed, plug = plugger.CheckPermits(username, "WEBSOCKET", r.RequestURI, false)
			// handle everything else
		} else {
			ro := MethodIsRo(r.Method)
			allowed, plug = plugger.CheckPermits(username, r.Method, r.RequestURI, ro)
		}
	}

	if allowed {
		return plugger.Forward(w, r, username, userSource, plug, USER_PERMIT)
	}

	// Execute login procedure, if available
	if username == "" {
		for _, plug := range plugger.Plugs {
			ok, code, err := plug.Login(w, r, plugger.Realm)
			if ok {
				return code, err
			}
		}
	}

	return Forbidden(w, r, username, userSource, nil, NO_PERMIT)
}

// CheckPermits checks permissions of a request
func (plugger *AuthPlugger) CheckPermits(username, method, path string, ro bool) (bool, Plug) {

	var permit *Permit
	var err error

	// Then get user/default permits
	if username != "" {

		for _, plug := range plugger.Plugs {

			permit, err = plug.GetPermit(username)
			if err != nil {
				fmt.Printf("[authplugger] failed to get user permit from %s: %s", plug.Name(), err)
				continue
			}
			if permit == nil {
				continue
			}
			if permit.Check(plugger, method, path, ro) {
				return true, plug
			}

			permit, err = plug.GetDefaultPermit()
			if err != nil {
				fmt.Printf("[authplugger] failed to get default permit from %s: %s", plug.Name(), err)
				continue
			}
			if permit != nil {
				if permit.Check(plugger, method, path, ro) {
					return true, plug
				}
			}

		}

	}

	// Lastly, check all public permits
	for _, plug := range plugger.Plugs {

		permit, err := plug.GetPublicPermit()
		if err != nil {
			fmt.Printf("[authplugger] failed to get public permit from %s: %s", plug.Name(), err)
			continue
		}
		if permit == nil {
			continue
		}
		if permit.Check(plugger, method, path, ro) {
			return true, plug
		}

	}

	return false, nil

}

func getUserForPrinting(username, userSource string) string {
	if username == "" {
		return ""
	}
	return fmt.Sprintf("[%s: %s] ", userSource, username)
}

func getPermitPlugForPrinting(plug Plug, permitType uint8) string {
	if plug == nil {
		return ""
	}
	switch permitType {
	case DEFAULT_PERMIT:
		return fmt.Sprintf("*%s ", plug.Name())
	case PUBLIC_PERMIT:
		return fmt.Sprintf("!%s ", plug.Name())
	default:
		return fmt.Sprintf("%s ", plug.Name())
	}
}

// Forward hands the request to the next middleware and adds some headers for information
func (plugger *AuthPlugger) Forward(w http.ResponseWriter, r *http.Request, username, userSource string, plug Plug, permitType uint8) (int, error) {

	// log
	printablePermit := getPermitPlugForPrinting(plug, permitType)
	fmt.Printf("[authplugger] %s%sgranted access: %s %s\n", getUserForPrinting(username, userSource), printablePermit, r.Method, r.RequestURI)

	// set username
	if username != "" {
		r.Header.Set("Caddy-Auth-User", username)
		r.Header.Set("Caddy-Auth-Source", userSource)
	} else {
		r.Header.Del("Caddy-Auth-User")
		r.Header.Del("Caddy-Auth-Source")
	}

	if printablePermit != "" {
		r.Header.Set("Caddy-Auth-Permit", printablePermit)
	} else {
		r.Header.Del("Caddy-Auth-Permit")
	}

	return plugger.Next.ServeHTTP(w, r)
}

// Forbidden logs why this request was forbidden and returns http.StatusForbidden
func Forbidden(w http.ResponseWriter, r *http.Request, username, userSource string, plug Plug, permitType uint8) (int, error) {

	// log
	fmt.Printf("[authplugger] %s%sdenied access: %s %s\n", getUserForPrinting(username, userSource), getPermitPlugForPrinting(plug, permitType), r.Method, r.RequestURI)

	return http.StatusForbidden, nil
}

// NewAuthPlugger creates a new AuthPlugger from configuration
func NewAuthPlugger(c *caddy.Controller) (*AuthPlugger, error) {

	new := AuthPlugger{}
	// cfg := httpserver.GetConfig(c)
	// var err error

	for c.Next() {

		// skip "authplugger"
		c.NextArg()

		switch c.Val() {
		case "allow_reading_parent_paths":
			new.ReadParentPath = true
		case "remove_prefix":
			// require argument
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			new.RemovePrefix = c.Val()
		case "realm":
			// require argument
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			new.Realm = c.Val()
		default:
			// get factory
			factory := GetFactory(c.Val())
			if factory == nil {
				return nil, fmt.Errorf("Unknown authplugger plug \"%s\" (line %d), did you maybe forget to load this plug?", c.Val(), c.Line())
			}
			// execute factory
			plug, err := factory(c)
			if err != nil {
				return nil, err
			}
			// add plug to plugs
			new.Plugs = append(new.Plugs, plug)
		}

	}

	return &new, nil
}
