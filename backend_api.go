package permission

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy"
)

// APIBackend authenticates users and gets permits through an API.
type APIBackend struct {
	CustomName string

	Lock          sync.RWMutex
	Users         map[string]*User
	Permits       map[string]*Permit
	DefaultPermit *Permit
	PublicPermit  *Permit

	UserURL   string
	PermitURL string

	LoginURL string

	AddPrefixes      []string
	AddWithoutPrefix bool

	CacheTime int64
	Cleanup   int64
}

// GetUsername authenticates and returns a username, if successful.
func (backend *APIBackend) GetUsername(r *http.Request) (username string, ok bool, err error) {

	var user *User

	backend.Lock.RLock()
	user, ok = backend.Users["auth="+r.Header.Get("Authorization")]
	if !ok {
		for _, cookie := range r.Cookies() {
			user, ok = backend.Users[cookie.Name+"="+cookie.Value]
			if ok {
				break
			}
		}
	}
	backend.Lock.RUnlock()

	if ok && user.ValidUntil > time.Now().Unix() {
		username = user.Username
		return
	}

	user, err = backend.AuthenticateUser(r)
	if user != nil {
		ok = true
	}
	return

}

// GetPermit returns the user permit of a user.
func (backend *APIBackend) GetPermit(username string) (permit *Permit, err error) {

	var ok bool

	backend.Lock.RLock()
	permit, ok = backend.Permits[username]
	backend.Lock.RUnlock()

	// Use >= to get an extra second compared to GetUsername, which may save a roundtrip if a request happens to occur between these two calls.
	if ok && permit.ValidUntil >= time.Now().Unix() {
		return
	}

	return backend.RefreshUserPermit(username)

}

// GetDefaultPermit returns the default permit.
func (backend *APIBackend) GetDefaultPermit() (*Permit, error) {
	return backend.DefaultPermit, nil
}

// GetPublicPermit returns the public permit.
func (backend *APIBackend) GetPublicPermit() (*Permit, error) {
	return backend.PublicPermit, nil
}

// Login redirects to the configured login URL.
func (backend *APIBackend) Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error) {
	url := strings.Replace(backend.LoginURL, "{{resource}}", r.RequestURI, -1)
	http.Redirect(w, r, url, 302)
	return true, 0, nil
}

// Name returns the name of the backend.
func (backend *APIBackend) Name() string {
	if backend.CustomName != "" {
		return fmt.Sprintf("%s:%s", BackendAPIName, backend.CustomName)
	}
	return BackendAPIName
}

func init() {
	RegisterBackend(BackendAPIName, NewAPIBackend)
}

// NewAPIBackend creates a new APIBackend.
func NewAPIBackend(c *caddy.Controller, now int64) (Backend, error) {

	new := APIBackend{
		Users:     make(map[string]*User),
		Permits:   make(map[string]*Permit),
		CacheTime: 600,
		Cleanup:   3600,
	}

	// we start right after the permission keyword
	for c.NextBlock() {
		switch c.Val() {
		case "name":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			new.CustomName = c.Val()
		case "user":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			new.UserURL = c.Val()
		case "permit":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			new.PermitURL = c.Val()
			if !strings.Contains(new.PermitURL, "{{username}}") {
				return nil, fmt.Errorf("permission > api > permit must contain a username placeholder: \"{{username}}\"")
			}
		case "login":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			new.LoginURL = c.Val()
		case "add_prefix":
			for c.NextArg() {
				new.AddPrefixes = append(new.AddPrefixes, c.Val())
			}
		case "add_without_prefix":
			new.AddWithoutPrefix = true
		case "cache", "cleanup":
			option := c.Val()
			// require argument
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			// parse integer
			i, err := strconv.ParseInt(c.Val(), 10, 64)
			if err != nil {
				return nil, c.ArgErr()
			}
			// set to 60 if less than that
			if i < 60 {
				i = 60
			}
			switch option {
			case "cache":
				new.CacheTime = i
			case "cleanup":
				new.Cleanup = i
			}
		default:
			return nil, c.ArgErr()
		}
	}

	// kick of cleaner
	go new.Cleaner()

	return &new, nil
}

// Response is a respone to an API request.
type Response struct {
	BasicAuth   bool
	Cookie      string
	Username    string
	Permissions map[string]string
}

// AuthenticateUser handles authentication via API.
func (backend *APIBackend) AuthenticateUser(r *http.Request) (*User, error) {

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	apiRequest, err := http.NewRequest("GET", backend.UserURL, nil)
	if err != nil {
		return nil, err
	}

	// Add source of original request

	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, err
	}

	apiRequest.Host = r.Host
	apiRequest.Header.Set("Host", r.Host)
	apiRequest.Header.Set("X-Real-IP", remoteIP)
	apiRequest.Header.Set("X-Forwarded-For", remoteIP)
	if r.TLS != nil {
		apiRequest.Header.Set("X-Forwarded-Proto", "https")
	} else {
		apiRequest.Header.Set("X-Forwarded-Proto", "http")
	}

	// Add basicauth and cookies
	rUsername, rPassword, ok := r.BasicAuth()
	if ok {
		apiRequest.SetBasicAuth(rUsername, rPassword)
	}
	for _, cookie := range r.Cookies() {
		apiRequest.AddCookie(cookie)
	}

	resp, err := client.Do(apiRequest)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case 200:

		apiResponse := &Response{}
		// var content []byte
		// _, err := resp.Body.Read(content)
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("could not read response: %s", err)
		}
		fmt.Println(string(content))
		err = json.Unmarshal(content, apiResponse)
		if err != nil {
			return nil, fmt.Errorf("could not unpack response: %s", err)
		}

		// process username

		var user *User
		switch {
		case apiResponse.BasicAuth:
			backend.Lock.Lock()
			user = NewUser(apiResponse.Username, backend.CacheTime)
			backend.Users["auth="+r.Header.Get("Authorization")] = user
			backend.Lock.Unlock()
		case apiResponse.Cookie != "":
			backend.Lock.Lock()
			user = NewUser(apiResponse.Username, backend.CacheTime)
			backend.Users[apiResponse.Cookie] = user
			backend.Lock.Unlock()
		default:
			return nil, errors.New("invalid response: missing either \"BasicAuth\" or \"Cookie\" for user identification")
		}

		// process optional permit

		if len(apiResponse.Permissions) > 0 {
			new, err := backend.CreatePermit(apiResponse)
			if err != nil {
				return nil, err
			}

			backend.Lock.Lock()
			backend.Permits[apiResponse.Username] = new
			backend.Lock.Unlock()
		}

		return user, nil

	case 404, 403:
		return nil, nil
	case 500:
		return nil, errors.New("server error")
	}

	return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

// RefreshUserPermit gets the Permit of an already authenticated user via API.
func (backend *APIBackend) RefreshUserPermit(username string) (*Permit, error) {

	url := strings.Replace(backend.PermitURL, "{{username}}", username, -1)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case 200:

		apiResponse := &Response{}
		var content []byte
		_, err := resp.Body.Read(content)
		if err != nil {
			return nil, fmt.Errorf("could not read response: %s", err)
		}
		err = json.Unmarshal(content, apiResponse)
		if err != nil {
			return nil, fmt.Errorf("could not unpack response: %s", err)
		}

		// process permit
		new, err := backend.CreatePermit(apiResponse)
		if err != nil {
			return nil, err
		}

		backend.Lock.Lock()
		switch username {
		case DefaultIdentifier:
			backend.DefaultPermit = new
		case PublicIdentifier:
			backend.PublicPermit = new
		default:
			backend.Permits[username] = new
		}
		backend.Lock.Unlock()

		return new, nil

	case 404, 403:
		new := NewPermit(backend.CacheTime, 0)
		backend.Lock.Lock()
		switch username {
		case DefaultIdentifier:
			backend.DefaultPermit = new
		case PublicIdentifier:
			backend.PublicPermit = new
		default:
			backend.Permits[username] = new
		}
		backend.Lock.Unlock()
		return new, nil

	case 500:
		return nil, errors.New("server error")
	}

	return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

// Cleaner periodically cleans up the APIBackend
// This consists of deleting all timed-out users and permits.
func (backend *APIBackend) Cleaner() {
	c := time.Tick(time.Duration(backend.Cleanup * 1000000000))
	for now := range c {
		nowUnix := now.Unix()
		backend.Lock.Lock()

		// clean users
		for auth, user := range backend.Users {
			if user.ValidUntil < nowUnix {
				delete(backend.Users, auth)
			}
		}

		// clean permits
		for username, permit := range backend.Permits {
			if permit.ValidUntil < nowUnix {
				delete(backend.Permits, username)
			}
		}

		backend.Lock.Unlock()
	}
}

// CreatePermit creates a new permit according to the configuration.
func (backend *APIBackend) CreatePermit(apiResponse *Response) (*Permit, error) {

	new := NewPermit(backend.CacheTime, 0)
	for path, methods := range apiResponse.Permissions {

		if len(backend.AddPrefixes) == 0 || backend.AddWithoutPrefix {
			err := new.AddRule(methods, path)
			if err != nil {
				return nil, fmt.Errorf("could not parse permission: %s", err)
			}
		}

		if len(backend.AddPrefixes) > 0 {
			for _, prefix := range backend.AddPrefixes {
				err := new.AddRule(methods, prefix+path)
				if err != nil {
					return nil, fmt.Errorf("could not parse permission: %s", err)
				}
			}
		}

	}
	new.Finalize()

	return new, nil

}
