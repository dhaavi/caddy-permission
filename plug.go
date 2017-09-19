package authplugger

import (
	"net/http"
	"sync"

	"github.com/mholt/caddy"
)

type Plug interface {
	GetUsername(r *http.Request) (username string, authSuccess bool, err error)
	GetPermit(username string) (*Permit, error)
	GetDefaultPermit() (*Permit, error)
	GetPublicPermit() (*Permit, error)
	Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error)
	Name() string
}

type PlugFactory func(c *caddy.Controller) (Plug, error)

var (
	plugFactories     map[string]PlugFactory
	plugFactoriesLock sync.RWMutex
)

func init() {
	plugFactories = make(map[string]PlugFactory)
}

func RegisterPlug(name string, plugFactory PlugFactory) {
	plugFactoriesLock.Lock()
	defer plugFactoriesLock.Unlock()
	plugFactories[name] = plugFactory
}

func GetFactory(name string) PlugFactory {
	plugFactoriesLock.RLock()
	defer plugFactoriesLock.RUnlock()
	factory, ok := plugFactories[name]
	if !ok {
		return nil
	}
	return factory
}
