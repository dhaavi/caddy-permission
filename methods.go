package authplugger

var (
	aliases = map[string][]string{
		"ro":  []string{"GET", "HEAD", "PROPFIND", "LOCK", "UNLOCK"},
		"rw":  []string{"GET", "HEAD", "PROPFIND", "LOCK", "UNLOCK", "POST", "PUT", "DELETE", "MKCOL", "PROPPATCH"},
		"ws":  []string{"WEBSOCKET"},
		"any": []string{"GET", "HEAD", "PROPFIND", "LOCK", "UNLOCK", "POST", "PUT", "DELETE", "MKCOL", "PROPPATCH", "WEBSOCKET"},
	}
)

func MethodIsRo(method string) bool {
	switch method {
	case "GET":
		return true
	case "HEAD":
		return true
	}
	return false
}

// special methods:
// MOVE: check DELETE on source and PUT on dest
// COPY: check GET on source and PUT on dest
