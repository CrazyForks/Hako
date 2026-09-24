package hako

import (
	"testing"
)


func TestResolverResetFiresOnEveryAppliedPathUpdate(t *testing.T) {
	cases := []struct {
		name                  string
		wasInitialized        bool
		identityChanged       bool
		addressFamiliesChange bool
		why                   string
	}{
		{
			name:            "interface identity changed",
			wasInitialized:  true,
			identityChanged: true,
			why:             "the old sockets are bound to an interface that is no longer the default",
		},
		{
			name:                  "address families changed",
			wasInitialized:        true,
			addressFamiliesChange: true,
			why:                   "a v4-only path cannot carry sockets opened for v6",
		},
		{
			name:           "capabilities only — the Personal Hotspot case",
			wasInitialized: true,
			why: "same interface, same families, but the source address and gateway moved; the " +
				"forwarded flags cannot distinguish this from a no-op, so it must reset",
		},
		{
			name:           "first update",
			wasInitialized: false,
			why:            "the resolver has never seen a path",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if !shouldResetResolverForPathUpdate(
				testCase.wasInitialized, testCase.identityChanged, testCase.addressFamiliesChange) {
				t.Fatalf("no reset for this update — %s", testCase.why)
			}
		})
	}
}

func TestConnectionTeardownStaysGatedWhileResolverResetDoesNot(t *testing.T) {
	const identityChanged, addressFamiliesChanged = false, false
	if identityChanged || addressFamiliesChanged {
		t.Fatal("this case is meant to be the one where the teardown condition is false")
	}
	if !shouldResetResolverForPathUpdate(true, identityChanged, addressFamiliesChanged) {
		t.Fatal("the resolver must reset where the connection teardown does not")
	}
}
