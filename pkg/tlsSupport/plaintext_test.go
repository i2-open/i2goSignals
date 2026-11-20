package tlsSupport

import "testing"

func TestIsPlaintextEndpoint(t *testing.T) {
	cases := map[string]bool{
		"https://rx.example/push": false,
		"HTTPS://rx.example/push": false,
		"http://rx.example/push":  true,
		"":                        true,
		"rx.example/push":         true,
		"ftp://rx.example":        true,
		"http://[::1]:namedport":  false, // unparseable: left to http.NewRequest
	}
	for raw, want := range cases {
		if got := IsPlaintextEndpoint(raw); got != want {
			t.Errorf("IsPlaintextEndpoint(%q) = %v, want %v", raw, got, want)
		}
	}
}
