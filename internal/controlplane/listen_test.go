package controlplane

import "testing"

// Audit H11: the control plane serves plain HTTP with an unauthenticated
// Enroll and approval callback, so by default it must not be reachable
// from the network — including configs that still carry the old ":8091".
func TestListenAddrDefaultsToLoopback(t *testing.T) {
	for in, want := range map[string]string{
		"":               "127.0.0.1:8091",
		":8091":          "127.0.0.1:8091", // old default: every interface
		":9000":          "127.0.0.1:9000",
		"127.0.0.1:8091": "127.0.0.1:8091",
		"0.0.0.0:8091":   "0.0.0.0:8091", // explicit opt-in is kept
		"[::]:8091":      "[::]:8091",
		"10.0.0.5:8091":  "10.0.0.5:8091",
	} {
		if got := ListenAddr(in); got != want {
			t.Errorf("ListenAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8091": true,
		"[::1]:8091":     true,
		"localhost:8091": true,
		"0.0.0.0:8091":   false,
		"[::]:8091":      false,
		"10.0.0.5:8091":  false,
		"garbage":        false,
	} {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
