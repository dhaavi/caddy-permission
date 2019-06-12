package permission

import (
	"net/http"

	"github.com/mholt/caddy"
)

// TLSBackend uses TLS client certificates for authentication.
type TLSBackend struct {
}

// GetUsername authenticates and returns a username, if successful.
func (backend *TLSBackend) GetUsername(r *http.Request) (string, bool, error) {
	// FIXME BEFORE 1.0: test what happens if a client certificate is provided, but client auth is not enabled in Caddy.
	// 1) Interestingly, if tls client auth is enabled and configured not to check the certificate, Caddy currently does not proceed with an invalid certificate.
	// 2) If tls auth is not configured, we do not receive a certificate here.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName, true, nil
	}
	return "", false, nil
}

// GetPermit returns nothing, as TLSBackend does not support permits.
func (backend *TLSBackend) GetPermit(username string) (*Permit, error) {
	return nil, nil
}

// GetDefaultPermit returns nothing, as TLSBackend does not support permits.
func (backend *TLSBackend) GetDefaultPermit() (*Permit, error) {
	return nil, nil
}

// GetPublicPermit returns nothing, as TLSBackend does not support permits.
func (backend *TLSBackend) GetPublicPermit() (*Permit, error) {
	return nil, nil
}

// Login is currently disabled for TLSBackend.
func (backend *TLSBackend) Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error) {
	return false, 0, nil
}

// Name returns the name of the plug.
func (backend *TLSBackend) Name() string {
	return BackendTLSName
}

func init() {
	RegisterBackend(BackendTLSName, NewTLSBackend)
}

// NewTLSBackend create a new TLSBackend.
func NewTLSBackend(c *caddy.Controller, now int64) (Backend, error) {

	new := TLSBackend{}

	args := c.RemainingArgs()
	if len(args) != 0 {
		return nil, c.ArgErr()
	}

	return &new, nil
}
