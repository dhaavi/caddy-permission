package permission

import (
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
	Rules      []*Rule
	ValidUntil int64
}

func (p Permit) Len() int {
	return len(p.Rules)
}

func (p Permit) Less(i, j int) bool {
	return len(p.Rules[i].Path) > len(p.Rules[j].Path)
}

func (p Permit) Swap(i, j int) {
	p.Rules[i], p.Rules[j] = p.Rules[j], p.Rules[i]
}

// Check checks a request against this permission object.
func (p *Permit) Check(handler *Handler, method, path string, ro bool) (allowed bool, matched bool) {
	for _, rule := range p.Rules {
		if rule.MatchesPath(path) {
			return rule.MatchesMethod(method), true
		} else if ro && handler.ReadParentPath && rule.MatchesParentPath(path) {
			return true, true
		}
	}
	return false, false
}

// NewPermit creates an empty Permit with the correct cache time.
func NewPermit(cacheTime int64, now int64) *Permit {
	if now == 0 {
		now = time.Now().Unix()
	}

	return &Permit{
		ValidUntil: now + cacheTime,
	}
}

// AddRule adds a permission to the Permit.
func (p *Permit) AddRule(methods, path string) error {
	new, err := NewRule(methods, path)
	if err != nil {
		return err
	}
	p.Rules = append(p.Rules, new)
	return nil
}

// Finalize does some final preparing/optimizing on the Permit.
func (p *Permit) Finalize() {
	// nothing to do here anymore, preserving for future use.
}
