package permission

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Handler (Permission Handler) is an authentication and authorization middleware
type Handler struct {
	Next httpserver.Handler

	Backends []Backend

	ReadParentPath bool
	RemovePrefix   string
	Realm          string

	SetBasicAuth string
	SetCookies   [][]string
}

// ServeHTTP implements the httpserver.Handler interface.
func (handler *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	var username string
	var userSource string

	var authSuccess bool
	var err error

	// First get username
	for _, backend := range handler.Backends {

		username, authSuccess, err = backend.GetUsername(r)
		if err != nil {
			fmt.Printf("[permission] failed to get user from %s: %s\n", backend.Name(), err)
			username = ""
			continue
		}
		if !authSuccess {
			username = ""
			continue
		}

		// we got the username, now check permissions
		userSource = backend.Name()
		break

	}

	var allowed bool
	var backend Backend

	switch r.Method {
	// handle MOVE
	case "MOVE":
		allowed, backend = handler.CheckPermits(username, "DELETE", r.RequestURI, false)
		if allowed {
			location := r.Header.Get("Location")
			if location != "" {
				allowed, backend = handler.CheckPermits(username, "PUT", location, false)
			} else {
				return http.StatusForbidden, errors.New("Failed to check permission: cannot MOVE without Location Header")
			}
		}
	// handle COPY
	case "COPY":
		allowed, backend = handler.CheckPermits(username, "GET", r.RequestURI, false)
		if allowed {
			location := r.Header.Get("Location")
			if location != "" {
				allowed, backend = handler.CheckPermits(username, "PUT", location, false)
			} else {
				return http.StatusForbidden, errors.New("Failed to check permission: cannot COPY without Location Header")
			}
		}
	// handle PATCH
	case "PATCH":
		dest := r.Header.Get("Destination")
		if dest != "" {
			if strings.ToLower(r.Header.Get("Action")) == "copy" {
				allowed, backend = handler.CheckPermits(username, "GET", r.RequestURI, false)
			} else {
				allowed, backend = handler.CheckPermits(username, "DELETE", r.RequestURI, false)
			}
			if allowed {
				allowed, backend = handler.CheckPermits(username, "PUT", dest, false)
			}
		} else {
			allowed, backend = handler.CheckPermits(username, r.Method, r.RequestURI, false)
		}
	default:
		// handle websocket upgrades
		if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
			allowed, backend = handler.CheckPermits(username, "WEBSOCKET", r.RequestURI, false)
			// handle everything else
		} else {
			ro := MethodIsRo(r.Method)
			allowed, backend = handler.CheckPermits(username, r.Method, r.RequestURI, ro)
		}
	}

	if allowed {
		return handler.Forward(w, r, username, userSource, backend, PermitTypeUser)
	}

	// Execute login (redirection) procedure, if available
	if username == "" {
		for _, backend := range handler.Backends {
			ok, code, err := backend.Login(w, r, handler.Realm)
			if ok {
				return code, err
			}
		}
	}

	return Forbidden(w, r, username, userSource, nil, PermitTypeNo)
}

// CheckPermits checks permissions of a request
func (handler *Handler) CheckPermits(username, method, path string, ro bool) (bool, Backend) {

	var permit *Permit
	var err error

	// Then get user/default permits
	if username != "" {
		for _, backend := range handler.Backends {

			permit, err = backend.GetPermit(username)
			if err != nil {
				fmt.Printf("[permission] failed to get user permit from %s: %s\n", backend.Name(), err)
				continue
			}
			if permit == nil {
				continue
			}
			allowed, matched := permit.Check(handler, method, path, ro)
			if matched {
				return allowed, backend
			}

			permit, err = backend.GetDefaultPermit()
			if err != nil {
				fmt.Printf("[permission] failed to get default permit from %s: %s\n", backend.Name(), err)
				continue
			}
			if permit != nil {
				allowed, matched = permit.Check(handler, method, path, ro)
				if matched {
					return allowed, backend
				}
			}

		}
	}

	// Lastly, check all public permits
	for _, backend := range handler.Backends {

		permit, err := backend.GetPublicPermit()
		if err != nil {
			fmt.Printf("[permission] failed to get public permit from %s: %s\n", backend.Name(), err)
			continue
		}
		if permit == nil {
			continue
		}
		allowed, matched := permit.Check(handler, method, path, ro)
		if matched {
			return allowed, backend
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

func getPermitBackendForPrinting(backend Backend, permitType uint8) string {
	if backend == nil {
		return ""
	}
	switch permitType {
	case PermitTypeDefault:
		return fmt.Sprintf("%s:default ", backend.Name())
	case PermitTypePublic:
		return fmt.Sprintf("%s:public ", backend.Name())
	default:
		return fmt.Sprintf("%s ", backend.Name())
	}
}

// Forward hands the request to the next middleware and adds some headers for information
func (handler *Handler) Forward(w http.ResponseWriter, r *http.Request, username, userSource string, backend Backend, permitType uint8) (int, error) {

	// log
	printablePermit := getPermitBackendForPrinting(backend, permitType)
	if debugPermissionPlugin {
		fmt.Printf("[permission] %s%sgranted access: %s %s\n", getUserForPrinting(username, userSource), printablePermit, r.Method, r.RequestURI)
	}

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

	// TODO: further investigate how Caddy handles the TRACE method
	// exempting TRACE prevents headers and cookies to be sent to client.
	if r.Method != "TRACE" {
		if handler.SetBasicAuth != "" {
			r.Header.Set("Authorization", "Basic "+handler.SetBasicAuth)
		}
		for _, cookie := range handler.SetCookies {
			r.AddCookie(&http.Cookie{
				Name:  cookie[0],
				Value: cookie[1],
			})
		}
	}

	return handler.Next.ServeHTTP(w, r)
}

// Forbidden logs why this request was forbidden and returns http.StatusForbidden
func Forbidden(w http.ResponseWriter, r *http.Request, username, userSource string, backend Backend, permitType uint8) (int, error) {
	if debugPermissionPlugin {
		fmt.Printf("[permission] %s%sdenied access: %s %s\n", getUserForPrinting(username, userSource), getPermitBackendForPrinting(backend, permitType), r.Method, r.RequestURI)
	}
	return http.StatusForbidden, fmt.Errorf("[permission] %s%sdenied access: %s %s", getUserForPrinting(username, userSource), getPermitBackendForPrinting(backend, permitType), r.Method, r.RequestURI)
}

// NewHandler creates a new Handler from configuration
func NewHandler(c *caddy.Controller, now int64) (*Handler, error) {
	if now == 0 {
		now = time.Now().Unix()
	}

	new := Handler{}
	// cfg := httpserver.GetConfig(c)
	// var err error

	for c.Next() {

		// skip "permission"
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
		case "set_basicauth":
			args := c.RemainingArgs()
			if len(args) != 2 {
				return nil, c.ArgErr()
			}
			new.SetBasicAuth = compileBasicAuthCreds(args[0], args[1])
		case "set_cookie":
			args := c.RemainingArgs()
			if len(args) != 2 {
				return nil, c.ArgErr()
			}
			new.SetCookies = append(new.SetCookies, []string{args[0], args[1]})
		default:
			// get factory
			factory := GetFactory(c.Val())
			if factory == nil {
				return nil, fmt.Errorf("unknown permission backend \"%s\" (line %d), did you maybe forget to include this plug in the build?", c.Val(), c.Line())
			}
			// execute factory
			backend, err := factory(c, now)
			if err != nil {
				return nil, err
			}
			// add plug to plugs
			new.Backends = append(new.Backends, backend)
		}

	}

	return &new, nil
}
