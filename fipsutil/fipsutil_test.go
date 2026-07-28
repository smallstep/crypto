package fipsutil

import (
	"strings"
	"testing"
)

func TestFipsUtil(t *testing.T) {
	t.Log("fipsutil.Enabled() is", Enabled())
	t.Log("fipsutil.Only() is", Only())
	t.Log("fipsutil.Version() is", Version())
	t.Log("fipsutil.BuildVersion() is", BuildVersion())
	t.Log("fipsutil.Validated() is", Validated())
}

// TestInvariants asserts the relationships that must hold however the test
// binary was built and run, so it passes under `go test`,
// `GOFIPS140=v1.0.0 go test`, and any GODEBUG=fips140 override of either.
func TestInvariants(t *testing.T) {
	if Only() && !Enabled() {
		t.Error("Only() implies Enabled()")
	}

	if Validated() {
		// A frozen module was selected, so the version must be a concrete one
		// and must agree with the recorded build setting. Go 1.26 and later
		// report the formal version ("v1.0.0") while the build setting carries
		// the snapshot suffix ("v1.0.0-c2097c7c"), so this is a prefix match.
		if got := Version(); got == "latest" {
			t.Error(`Validated() is true but Version() is "latest"`)
		} else if !strings.HasPrefix(BuildVersion(), got) {
			t.Errorf("BuildVersion() = %q, want it to start with Version() = %q", BuildVersion(), got)
		}

		return
	}

	if got := Version(); got != "latest" {
		t.Errorf("Version() = %q, want %q when no frozen module is linked", got, "latest")
	}
}
