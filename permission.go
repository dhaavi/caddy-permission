package authplugger

import (
	"strings"
)

// Permission holds permission information related to a specific path
type Permission struct {
	Path                string
	Methods             []string
	MethodsAreBlacklist bool
}

const (
	blacklistChar = "~"
)

var (
	errUnknownMethod = "failed to create Permission: method \"%s\" unknown."
)

// MatchesMethod checks if the permission matches the given HTTP method.
func (p *Permission) MatchesMethod(method string) bool {
	found := false
	for _, m := range p.Methods {
		if method == m {
			found = true
			break
		}
	}
	if found {
		return !p.MethodsAreBlacklist
	}
	return p.MethodsAreBlacklist
}

// MatchesPath checks if the permission matches the given HTTP request path.
func (p *Permission) MatchesPath(path string) bool {
	return strings.HasPrefix(path, p.Path)
}

// MatchesParentPath checks if the HTTP request path is a parent of the permission path.
func (p *Permission) MatchesParentPath(path string) bool {
	return strings.HasPrefix(p.Path, path)
}

// NewPermission creates a new permission with the given concatenated method string and path
func NewPermission(methods, path string) (*Permission, error) {
	new := Permission{
		Path: path,
	}

	if methods == blacklistChar {
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
		shortcuts, ok := aliases[method]
		if ok {
			new.Methods = append(new.Methods, shortcuts...)
		} else {
			new.Methods = append(new.Methods, method)
		}
	}

	return &new, nil
}
