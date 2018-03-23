package authplugger

// Backend constants
const (
	BackendBasic uint8 = iota
	BackendAPI
	BackendTLS

	BackendBasicName = "basic"
	BackendAPIName   = "api"
	BackendTLSName   = "tls"

	DefaultShort = "*"
	DefaultLong  = "default"
	PublicShort  = "!"
	PublicLong   = "public"
)
