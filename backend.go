package permission

import (
	"net/http"
	"sync"

	"github.com/mholt/caddy"
)

// Backend is an interface for adding backend plugins
type Backend interface {
	GetUsername(r *http.Request) (username string, authSuccess bool, err error)
	GetPermit(username string) (*Permit, error)
	GetDefaultPermit() (*Permit, error)
	GetPublicPermit() (*Permit, error)
	Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error)
	Name() string
}

// BackendFactory creates a plug
type BackendFactory func(c *caddy.Controller, now int64) (Backend, error)

var (
	backendFactories     map[string]BackendFactory
	backendFactoriesLock sync.RWMutex
)

func init() {
	backendFactories = make(map[string]BackendFactory)
}

// RegisterBackend registers a Permission backend for use
func RegisterBackend(name string, plugFactory BackendFactory) {
	backendFactoriesLock.Lock()
	defer backendFactoriesLock.Unlock()
	backendFactories[name] = plugFactory
}

// GetFactory returns the factory for the given backend name
func GetFactory(name string) BackendFactory {
	backendFactoriesLock.RLock()
	defer backendFactoriesLock.RUnlock()
	factory, ok := backendFactories[name]
	if !ok {
		return nil
	}
	return factory
}
