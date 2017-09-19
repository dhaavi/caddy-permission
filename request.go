package authplugger

type Response struct {
	Basic       string
	Cookie      string
	User        string
	Permissions map[string]string
}
