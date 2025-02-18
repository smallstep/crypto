package fipsutil

import "testing"

func TestFipsUtil(t *testing.T) {
	t.Log("fipsutil.Enabled() is", Enabled())
	t.Log("fipsutil.Only() is", Only())
}
