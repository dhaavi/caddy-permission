package authplugger

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type AuthPlugger struct {
	Next httpserver.Handler

	Plugs []Plug

	PublicPermit     *Permit
	PublicPermitLock sync.RWMutex
	PublicPermitTTL  int64

	ReadParentPath bool
	RemovePrefix   string
	CacheTTL       int64
	Realm          string
}

// ServeHTTP implements the httpserver.Handler interface.
func (plugger *AuthPlugger) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	var userPermit *Permit
	var effectivePermit *Permit

	var authSuccess bool
	var err error

	ro := MethodIsRo(r.Method)

	// If GetUserPermit or auth failes, continue
	// If user does not exist, continue
	// If user exists, lock to that plug and fail if GetDefaultPermit failes
	for _, plug := range plugger.Plugs {

		userPermit, authSuccess, err = plug.GetUserPermit(r)
		if err != nil {
			// FIXME: log
			userPermit = nil
			continue
		}
		if !authSuccess {
			userPermit = nil
			continue
		}

		fmt.Printf("[debug] [authplugger] [%s] authenticated\n", userPermit.Username)

		if userPermit.Check(plugger, r.Method, r.RequestURI, ro) {
			return plugger.Forward(w, r, userPermit, effectivePermit)
			// return plugger.Next.ServeHTTP(w, r)
		}

		effectivePermit, err = plug.GetDefaultPermit()
		if err != nil {
			// FIXME: log
			fmt.Printf("[debug] [authplugger] [%s] failed to get default permit: %s\n", userPermit.Username, err)
			return Forbidden(w, r, userPermit, effectivePermit)
		}

		if effectivePermit != nil {
			if effectivePermit.Check(plugger, r.Method, r.RequestURI, ro) {
				return plugger.Forward(w, r, userPermit, effectivePermit)
			}
		}

	}

	// If request could not be authenticated in any plug, check all plugs for a public permit.
	effectivePermit = plugger.GetPublicPermit()
	if effectivePermit != nil {
		fmt.Printf("[authplugger] checking public permit\n")
		if effectivePermit.Check(plugger, r.Method, r.RequestURI, ro) {
			return plugger.Forward(w, r, userPermit, effectivePermit)
		}
	}

	// Redirect to Login Procedure, if available
	for _, plug := range plugger.Plugs {
		login := plug.LoginResponder()
		if login != nil {
			fmt.Printf("[authplugger] redirecting to login (backend: %s)\n", plug.Name())
			return login(w, r, plugger.Realm)
		}
	}

	return Forbidden(w, r, userPermit, effectivePermit)
}

func (plugger *AuthPlugger) GetPublicPermit() *Permit {
	// Check Cache
	plugger.PublicPermitLock.RLock()
	if plugger.PublicPermitTTL > time.Now().Unix() {
		defer plugger.PublicPermitLock.RUnlock()
		return plugger.PublicPermit
	}
	plugger.PublicPermitLock.RUnlock()

	// Fetch
	plugger.PublicPermitLock.Lock()
	defer plugger.PublicPermitLock.Unlock()
	// First plug to deliver public permit wins, cache that for CacheTTL
	for _, plug := range plugger.Plugs {
		permit, err := plug.GetPublicPermit()
		if err != nil {
			// FIXME: log
			continue
		}
		plugger.PublicPermit = permit
		break
	}
	return plugger.PublicPermit
}

func getUserForPrinting(permit *Permit) string {
	if permit == nil {
		return ""
	}
	return fmt.Sprintf("[%s: %s] ", permit.Source(), permit.Username)
}

func getBackendForPrinting(permit *Permit) string {
	if permit == nil {
		return ""
	}
	switch permit.Username {
	case "*":
		return fmt.Sprintf("*%s ", permit.Source())
	case "!":
		return fmt.Sprintf("!%s ", permit.Source())
	default:
		return fmt.Sprintf("%s ", permit.Source())
	}
}

func (plugger *AuthPlugger) Forward(w http.ResponseWriter, r *http.Request, userPermit, effectivePermit *Permit) (int, error) {

	// log
	fmt.Printf("[authplugger] %s%sgranted access: %s %s\n", getUserForPrinting(userPermit), getBackendForPrinting(effectivePermit), r.Method, r.RequestURI)

	// set username
	if userPermit != nil {
		r.Header.Set("X-AUTHPLUGGER-USER", userPermit.Username)
	} else {
		r.Header.Del("X-AUTHPLUGGER-USER")
	}

	// set chain TODO: which chain? user or effective?
	// switch effectivePermit.Username {
	// case "*":
	// 	r.Header.Set("X-AUTHPLUGGER-CHAIN", "Default")
	// case "!":
	// 	r.Header.Set("X-AUTHPLUGGER-CHAIN", "Public")
	// default:
	// 	r.Header.Set("X-AUTHPLUGGER-CHAIN", "User")
	// }

	// set backend TODO: which backend? user or effective?
	// r.Header.Set("X-AUTHPLUGGER-BACKEND", permit.Source())

	return plugger.Next.ServeHTTP(w, r)
}

func Forbidden(w http.ResponseWriter, r *http.Request, userPermit, effectivePermit *Permit) (int, error) {
	// log
	fmt.Printf("[authplugger] %s%sdenied access: %s %s\n", getUserForPrinting(userPermit), getBackendForPrinting(effectivePermit), r.Method, r.RequestURI)
	return http.StatusForbidden, nil
}

func NewAuthPlugger(c *caddy.Controller) (*AuthPlugger, error) {

	new := AuthPlugger{
		CacheTTL: 600,
	}
	// cfg := httpserver.GetConfig(c)
	// var err error

	for c.Next() {

		// skip "authplugger"
		c.NextArg()

		switch c.Val() {
		case "allow_reading_parent_paths":
			new.ReadParentPath = true
		case "cache_ttl":
			// require argument
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			// parse integer
			i, err := strconv.ParseInt(c.Val(), 10, 64)
			if err != nil {
				return nil, c.ArgErr()
			}
			// set to zero if negative
			if i < 0 {
				i = 0
			}
			new.CacheTTL = i
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
