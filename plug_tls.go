package authplugger

import (
	"net/http"

	"github.com/mholt/caddy"
)

type TLSAuthPlug struct {
	SetBasicAuth string
	SetCookies   [][]string
}

func (plug *TLSAuthPlug) GetUsername(r *http.Request) (string, bool, error) {
	// FIXME BEFORE 1.0: test what happens if a client certificate is provided, but client auth is not enabled in Caddy.
	// 1) Interestingly, if tls client auth is enabled and configured not to check the certificate, Caddy currently does not proceed with an invalid certificate.
	// 2) If tls auth is not configured, we do not receive a certificate here.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		plug.AddAuth(r)
		return r.TLS.PeerCertificates[0].Subject.CommonName, true, nil
	}
	return "", false, nil
}

func (plug *TLSAuthPlug) GetPermit(username string) (*Permit, error) {
	return nil, nil
}

func (plug *TLSAuthPlug) GetDefaultPermit() (*Permit, error) {
	return nil, nil
}

func (plug *TLSAuthPlug) GetPublicPermit() (*Permit, error) {
	return nil, nil
}

func (plug *TLSAuthPlug) Login(w http.ResponseWriter, r *http.Request, realm string) (bool, int, error) {
	return false, 0, nil
}

func (plug *TLSAuthPlug) AddAuth(r *http.Request) {
	// FIXME BEFORE 1.0: further investigate how Caddy handles the TRACE method
	if r.Method != "TRACE" {
		if plug.SetBasicAuth != "" {
			r.Header.Set("Authorization", "Basic "+plug.SetBasicAuth)
		}
		for _, cookie := range plug.SetCookies {
			r.AddCookie(&http.Cookie{
				Name:  cookie[0],
				Value: cookie[1],
			})
		}
	}
}

func (plug *TLSAuthPlug) Name() string {
	return "tls"
}

func init() {
	RegisterPlug("tls", NewTLSAuthPlug)
}

func NewTLSAuthPlug(c *caddy.Controller) (Plug, error) {

	new := TLSAuthPlug{}

	// we start right after the plugin keyword
	for c.NextBlock() {
		switch c.Val() {
		case "setbasicauth":
			args := c.RemainingArgs()
			if len(args) != 2 {
				return nil, c.ArgErr()
			}
			new.SetBasicAuth = compileBasicAuthCreds(args[0], args[1])
		case "setcookie":
			args := c.RemainingArgs()
			if len(args) != 2 {
				return nil, c.ArgErr()
			}
			new.SetCookies = append(new.SetCookies, []string{args[0], args[1]})
		default:
			c.ArgErr()
		}
	}

	return &new, nil

}
