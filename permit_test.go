package permission

import (
	"testing"
)

var (
	testPermitsHandler = &Handler{
		ReadParentPath: true,
	}
)

func testPermit(t *testing.T, permit *Permit, method, path string, shouldMatch, shouldBeAllowed bool) {
	allowed, matched := permit.Check(testPermitsHandler, method, path, MethodIsRo(method))
	if matched != shouldMatch {
		t.Errorf("expected %s %s is match=%v, but expected to be match=%v", method, path, matched, shouldMatch)
		return
	}
	if matched {
		if allowed != shouldBeAllowed {
			t.Errorf("expected %s %s is allow=%v, but expected to be allow=%v", method, path, allowed, shouldBeAllowed)
		}
	}
}

func addRule(permit *Permit, methods, path string) {
	err := permit.AddRule(methods, path)
	if err != nil {
		panic(err)
	}
}

func TestPermits(t *testing.T) {
	p := NewPermit(0, 0)
	addRule(p, "ro", "/public/")
	addRule(p, "rw", "/private/")
	addRule(p, "none", "/shared/vault/")
	addRule(p, "any", "/shared/")
	addRule(p, "CRAZY", "/stuff/")
	p.Finalize()

	testPermit(t, p, "GET", "/a", false, false)
	testPermit(t, p, "POST", "/b", false, false)

	testPermit(t, p, "GET", "/public/test.html", true, true)
	testPermit(t, p, "POST", "/public/test.html", true, false)
	testPermit(t, p, "GET", "/private/test.html", true, true)
	testPermit(t, p, "POST", "/private/test.html", true, true)

	testPermit(t, p, "GET", "/shared/test.html", true, true)
	testPermit(t, p, "POST", "/shared/test.html", true, true)
	testPermit(t, p, "UNKNOWN", "/shared/test.html", true, true)
	testPermit(t, p, "GET", "/shared/vault/test.html", true, false)
	testPermit(t, p, "POST", "/shared/vault/test.html", true, false)

	testPermit(t, p, "GET", "/stuff/test.html", true, false)
	testPermit(t, p, "CRAZY", "/stuff/test.html", true, true)
}
