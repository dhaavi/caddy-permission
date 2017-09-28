package authplugger

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy"
)

type ApiAuthPlug struct {
	CustomName string

	Lock          sync.RWMutex
	Users         map[string]*User
	Permits       map[string]*Permit
	DefaultPermit *Permit
	PublicPermit  *Permit

	UserURL   string
	PermitURL string

	LoginURL string

	AddPrefixes []string
	AddNoPrefix bool

	CacheTime int64
	Cleanup   int64
}

func (plug *ApiAuthPlug) GetUsername(r *http.Request) (username string, ok bool, err error) {

	var user *User

	plug.Lock.RLock()
	user, ok = plug.Users["auth="+r.Header.Get("Authorization")]
	if !ok {
		for _, cookie := range r.Cookies() {
			user, ok = plug.Users[cookie.Name+"="+cookie.Value]
			if ok {
				break
			}
		}
	}
	plug.Lock.RUnlock()

	if ok && user.ValidUntil > time.Now().Unix() {
		username = user.Username
		return
	}

	user, err = plug.ApiUserRequest(r)
	if user != nil {
		ok = true
	}
	return

}

func (plug *ApiAuthPlug) GetPermit(username string) (permit *Permit, err error) {

	var ok bool

	plug.Lock.RLock()
	permit, ok = plug.Permits[username]
	plug.Lock.RUnlock()

	// Use >= to get an extra second compared to GetUsername, which may save a roundtrip if a request happens to occur between these two calls.
	if ok && permit.ValidUntil >= time.Now().Unix() {
		return
	}

	return plug.ApiPermRequest(username)

}

func (plug *ApiAuthPlug) GetDefaultPermit() (*Permit, error) {
	return plug.DefaultPermit, nil
}

func (plug *ApiAuthPlug) GetPublicPermit() (*Permit, error) {
	return plug.PublicPermit, nil
}

func (plug *ApiAuthPlug) Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error) {
	url := strings.Replace(plug.LoginURL, "{{resource}}", r.RequestURI, -1)
	http.Redirect(w, r, url, 302)
	return true, 0, nil
}

func (plug *ApiAuthPlug) Name() string {
	if plug.CustomName != "" {
		return "api:" + plug.CustomName
	}
	return "api"
}

func init() {
	RegisterPlug("api", NewApiAuthPlug)
}

func NewApiAuthPlug(c *caddy.Controller) (Plug, error) {

	new := ApiAuthPlug{
		Users:     make(map[string]*User),
		Permits:   make(map[string]*Permit),
		CacheTime: 600,
		Cleanup:   3600,
	}

	// we start right after the plugin keyword
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
				return nil, fmt.Errorf("authplugger > api > permit must contain a username placeholder: \"{{username}}\"")
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
		case "add_no_prefix":
			new.AddNoPrefix = true
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
			// set to zero if negative
			if i < 0 {
				i = 0
			}
			switch option {
			case "cache":
				new.CacheTime = i
			case "cleanup":
				new.Cleanup = i
			}
		default:
			c.ArgErr()
		}
	}

	// kick of cleaner
	go new.Cleaner()

	return &new, nil

}

type Response struct {
	BasicAuth   bool
	Cookie      string
	Username    string
	Permissions map[string]string
}

func (plug *ApiAuthPlug) ApiUserRequest(r *http.Request) (*User, error) {

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	apiRequest, err := http.NewRequest("GET", plug.UserURL, nil)
	if err != nil {
		return nil, err
	}

	// Add source of original request
	apiRequest.Header.Add("X-Real-IP", r.RemoteAddr)
	apiRequest.Header.Add("X-Forwarded-For", r.RemoteAddr)
	if r.TLS != nil {
		apiRequest.Header.Add("X-Forwarded-Proto", "https")
	} else {
		apiRequest.Header.Add("X-Forwarded-Proto", "http")
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
			plug.Lock.Lock()
			user = NewUser(apiResponse.Username, plug.CacheTime)
			plug.Users["auth="+r.Header.Get("Authorization")] = user
			plug.Lock.Unlock()
		case apiResponse.Cookie != "":
			plug.Lock.Lock()
			user = NewUser(apiResponse.Username, plug.CacheTime)
			plug.Users[apiResponse.Cookie] = user
			plug.Lock.Unlock()
		default:
			return nil, errors.New("invalid response: missing either \"BasicAuth\" or \"Cookie\" for user identification")
		}

		// process optional permit

		if len(apiResponse.Permissions) > 0 {
			new, err := plug.CreatePermit(apiResponse)
			if err != nil {
				return nil, err
			}

			plug.Lock.Lock()
			plug.Permits[apiResponse.Username] = new
			plug.Lock.Unlock()
		}

		return user, nil

	case 404, 403:
		return nil, nil
	case 500:
		return nil, errors.New("server error")
	}

	return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func (plug *ApiAuthPlug) ApiPermRequest(username string) (*Permit, error) {

	url := strings.Replace(plug.PermitURL, "{{username}}", username, -1)

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
		new, err := plug.CreatePermit(apiResponse)
		if err != nil {
			return nil, err
		}

		plug.Lock.Lock()
		switch username {
		case "*":
			plug.DefaultPermit = new
		case "!":
			plug.PublicPermit = new
		default:
			plug.Permits[username] = new
		}
		plug.Lock.Unlock()

		return new, nil

	case 404, 403:
		new := NewPermit(plug.CacheTime)
		plug.Lock.Lock()
		switch username {
		case "*":
			plug.DefaultPermit = new
		case "!":
			plug.PublicPermit = new
		default:
			plug.Permits[username] = new
		}
		plug.Lock.Unlock()
		return new, nil

	case 500:
		return nil, errors.New("server error")
	}

	return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

// Cleaner periodically cleans up the ApiAuthPlug
// This consists of deleting all timed-out users and permits.
func (plug *ApiAuthPlug) Cleaner() {
	c := time.Tick(time.Duration(plug.Cleanup * 1000000000))
	for now := range c {
		nowUnix := now.Unix()
		plug.Lock.Lock()

		// clean users
		for auth, user := range plug.Users {
			if user.ValidUntil < nowUnix {
				delete(plug.Users, auth)
			}
		}

		// clean permits
		for username, permit := range plug.Permits {
			if permit.ValidUntil < nowUnix {
				delete(plug.Permits, username)
			}
		}

		plug.Lock.Unlock()
	}
}

func (plug *ApiAuthPlug) CreatePermit(apiResponse *Response) (*Permit, error) {

	new := NewPermit(plug.CacheTime)
	for path, methods := range apiResponse.Permissions {

		if len(plug.AddPrefixes) == 0 || plug.AddNoPrefix {
			err := new.AddPermission(methods, path)
			if err != nil {
				return nil, fmt.Errorf("could not parse permission: %s", err)
			}
		}

		if len(plug.AddPrefixes) > 0 {
			for _, prefix := range plug.AddPrefixes {
				err := new.AddPermission(methods, prefix+path)
				if err != nil {
					return nil, fmt.Errorf("could not parse permission: %s", err)
				}
			}
		}

	}
	new.Finalize()

	return new, nil

}
