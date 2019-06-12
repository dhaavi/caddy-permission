package permission

// Backend constants
const (
	BackendBasic uint8 = iota
	BackendAPI
	BackendTLS

	BackendBasicName = "basic"
	BackendAPIName   = "api"
	BackendTLSName   = "tls"

	DefaultIdentifier = "default"
	PublicIdentifier  = "public"
)
