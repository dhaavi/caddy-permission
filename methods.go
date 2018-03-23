package authplugger

var (
	aliases = map[string][]string{
		"ro":  []string{"GET", "HEAD", "PROPFIND", "OPTIONS", "LOCK", "UNLOCK"},
		"rw":  []string{"GET", "HEAD", "PROPFIND", "OPTIONS", "LOCK", "UNLOCK", "POST", "PUT", "DELETE", "MKCOL", "PROPPATCH"},
		"ws":  []string{"WEBSOCKET"},
		"any": []string{"GET", "HEAD", "PROPFIND", "OPTIONS", "LOCK", "UNLOCK", "POST", "PUT", "DELETE", "MKCOL", "PROPPATCH", "WEBSOCKET"},
	}
)

// MethodIsRo returns whether the supplied method is a "read only" method.
func MethodIsRo(method string) bool {
	switch method {
	case "GET", "HEAD", "PROPFIND", "OPTIONS":
		return true
	}
	return false
}

// special methods:
// MOVE: check DELETE on source and PUT on dest
// COPY: check GET on source and PUT on dest
// WEBSOCKET: check if Upgrade Header is present
// PATCH: treated as special if "Destination" Header is present:
//   like COPY if Header "Action: copy" is present, else
//   like MOVE
//   (this behaviour was observed in https://github.com/hacdias/filemanager)
