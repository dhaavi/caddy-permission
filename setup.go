package permission

import (
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("permission", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new permission middleware instance.
func setup(c *caddy.Controller) error {

	handler, err := NewHandler(c, time.Now().Unix())
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)
	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		handler.Next = next
		return handler
	})

	return nil
}
