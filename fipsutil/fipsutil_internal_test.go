//go:build go1.24

package fipsutil

import "testing"

// TestValidated exercises the classification Validated() applies. The build
// setting it reads cannot be changed by a test, so the cached value is swapped
// directly rather than the reading of it being mocked.
func TestValidated(t *testing.T) {
	tests := []struct {
		buildVersion string
		want         bool
	}{
		{"", false},
		{"off", false},
		{"latest", false},
		{"v1.0.0-c2097c7c", true},
		{"v1.26.0", true},
	}

	// Run the sync.Once now so the assignments below are not overwritten by a
	// later first call.
	BuildVersion()

	saved := buildVersion
	t.Cleanup(func() { buildVersion = saved })

	for _, tt := range tests {
		t.Run(tt.buildVersion, func(t *testing.T) {
			buildVersion = tt.buildVersion
			if got := Validated(); got != tt.want {
				t.Errorf("Validated() with BuildVersion() = %q is %v, want %v", tt.buildVersion, got, tt.want)
			}
		})
	}
}
