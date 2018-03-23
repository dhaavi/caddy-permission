package authplugger

import (
	"sort"
	"time"
)

// Permit Types
const (
	PermitTypeNo uint8 = iota
	PermitTypeUser
	PermitTypeDefault
	PermitTypePublic
)

// Permit holds permissions and their expiration time.
type Permit struct {
	Permissions []*Permission
	ValidUntil  int64
}

func (p Permit) Len() int {
	return len(p.Permissions)
}

func (p Permit) Less(i, j int) bool {
	return len(p.Permissions[i].Path) > len(p.Permissions[j].Path)
}

func (p Permit) Swap(i, j int) {
	p.Permissions[i], p.Permissions[j] = p.Permissions[j], p.Permissions[i]
}

// Check checks a request against this permission object.
func (p Permit) Check(ap *AuthPlugger, method, path string, ro bool) bool {
	for _, perm := range p.Permissions {
		if perm.MatchesPath(path) {
			return perm.MatchesMethod(method)
		} else if ro && ap.ReadParentPath && perm.MatchesParentPath(path) {
			return true
		}
	}
	return false
}

// NewPermit creates an empty Permit with the correct cache time.
func NewPermit(cacheTime int64) *Permit {
	return &Permit{
		ValidUntil: time.Now().Unix() + cacheTime,
	}
}

// AddPermission adds a permission to the Permit.
func (p *Permit) AddPermission(methods, path string) error {
	new, err := NewPermission(methods, path)
	if err != nil {
		return err
	}
	p.Permissions = append(p.Permissions, new)
	return nil
}

// Finalize sort the permissions and must be called when all permissions were added to the Permit.
func (p *Permit) Finalize() {
	sort.Sort(*p)
}
