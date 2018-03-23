package authplugger

import (
	"net/http"
	"sync"

	"github.com/mholt/caddy"
)

// Plug is an interface for adding plugins to authplugger
type Plug interface {
	GetUsername(r *http.Request) (username string, authSuccess bool, err error)
	GetPermit(username string) (*Permit, error)
	GetDefaultPermit() (*Permit, error)
	GetPublicPermit() (*Permit, error)
	Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error)
	Name() string
}

// PlugFactory creates a plug
type PlugFactory func(c *caddy.Controller) (Plug, error)

var (
	plugFactories     map[string]PlugFactory
	plugFactoriesLock sync.RWMutex
)

func init() {
	plugFactories = make(map[string]PlugFactory)
}

// RegisterPlug registers an Authplugger plug for use
func RegisterPlug(name string, plugFactory PlugFactory) {
	plugFactoriesLock.Lock()
	defer plugFactoriesLock.Unlock()
	plugFactories[name] = plugFactory
}

// GetFactory returns the factory for the given plug name
func GetFactory(name string) PlugFactory {
	plugFactoriesLock.RLock()
	defer plugFactoriesLock.RUnlock()
	factory, ok := plugFactories[name]
	if !ok {
		return nil
	}
	return factory
}
