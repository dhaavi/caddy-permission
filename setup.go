package authplugger

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("authplugger", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Authplugger middleware instance.
func setup(c *caddy.Controller) error {

	authPlugger, err := NewAuthPlugger(c)
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)
	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		authPlugger.Next = next
		return authPlugger
	})

	return nil
}
