package authplugger

import (
	"sort"
	"time"
)

type Permit struct {
	Username    string
	Source      func() string `json:"-"`
	Permissions []*Permission
	Fetched     int64
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

func NewPermit(sourceName func() string) *Permit {
	return &Permit{
		Source:  sourceName,
		Fetched: time.Now().Unix(),
	}
}

func (p *Permit) AddPermission(methods, path string) error {
	new, err := NewPermission(methods, path)
	if err != nil {
		return err
	}
	p.Permissions = append(p.Permissions, new)
	return nil
}

func (p *Permit) Finalize() {
	sort.Sort(*p)
}
