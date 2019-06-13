package permission

import "flag"

var (
	printDebug bool
	printError bool
)

func init() {
	flag.BoolVar(&printDebug, "debug-permission", false, "Enable debug messages (to stdout) for the permission plugin")
	flag.BoolVar(&printError, "error-permission", false, "Enable error messages (to stdout) for the permission plugin")
}
