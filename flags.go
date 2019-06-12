package permission

import "flag"

var (
	debugPermissionPlugin bool
)

func init() {
	flag.BoolVar(&debugPermissionPlugin, "debug-permission-plugin", false, "Enable debug logging for the permission plugin")
}
