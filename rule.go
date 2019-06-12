package permission

import (
	"strings"
)

// Rule holds permission information related to a specific path
type Rule struct {
	Path                string
	Methods             []string
	MethodsAreBlacklist bool
}

const (
	blacklistChar = "~"
)

var (
	errUnknownMethod = "failed to create Rule: method \"%s\" unknown."
)

// MatchesMethod checks if the permission matches the given HTTP method.
func (r *Rule) MatchesMethod(method string) bool {
	found := false
	for _, m := range r.Methods {
		if method == m {
			found = true
			break
		}
	}
	if found {
		return !r.MethodsAreBlacklist
	}
	return r.MethodsAreBlacklist
}

// MatchesPath checks if the permission rule matches the given HTTP request path.
func (r *Rule) MatchesPath(path string) bool {
	if len(path) < len(r.Path) {
		return false
	}
	return strings.HasPrefix(path, r.Path)
}

// MatchesParentPath checks if the HTTP request path is a parent of the permission rule path.
func (r *Rule) MatchesParentPath(path string) bool {
	if len(path) <= len(r.Path) {
		return false
	}
	return strings.HasPrefix(r.Path, path)
}

// NewRule creates a new permission rule with the given concatenated method string and path
func NewRule(methods, path string) (*Rule, error) {
	new := Rule{
		Path: path,
	}

	if methods == blacklistChar || methods == "none" {
		return &new, nil
	}

	if methods == "any" {
		new.MethodsAreBlacklist = true
		return &new, nil
	}

	if strings.HasPrefix(methods, blacklistChar) {
		new.MethodsAreBlacklist = true
		methods = strings.TrimLeft(methods, blacklistChar)
	}

	splitted := strings.Split(methods, ",")
	for _, method := range splitted {
		method = strings.TrimSpace(method)
		shortcuts, ok := aliases[method]
		if ok {
			new.Methods = append(new.Methods, shortcuts...)
		} else {
			new.Methods = append(new.Methods, method)
		}
	}

	return &new, nil
}
