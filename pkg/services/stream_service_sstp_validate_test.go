package services

import (
	"strings"
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// A bare-hostname issuer is a legal StringOrURI (RFC 7519 s2) and must not be
// refused. The regression this guards is a FORWARD direction, which carries the
// issuer its upstream asserts rather than one this server chose: refusing a
// non-URI issuer made those pairs uncreatable.
func TestValidateSstpDirectionAcceptsNonUriIssAndAud(t *testing.T) {
	cases := []struct {
		name string
		dir  model.SstpDirection
	}{
		{"bare hostname issuer", model.SstpDirection{
			Iss:  "cluster.scim.example.com",
			Aud:  []string{"https://beta.example.com"},
			Mode: model.SstpModeForward,
		}},
		{"bare audience", model.SstpDirection{
			Iss:  "https://alpha.example.com",
			Aud:  []string{"beta"},
			Mode: model.SstpModePublish,
		}},
		{"both bare", model.SstpDirection{
			Iss:  "alpha",
			Aud:  []string{"beta", "gamma"},
			Mode: model.SstpModeImport,
		}},
		{"urn issuer is still a URI", model.SstpDirection{
			Iss:  "urn:example:alpha",
			Aud:  []string{"https://beta.example.com"},
			Mode: model.SstpModePublish,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSstpDirection("primary", tc.dir); err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
		})
	}
}

// Presence is still required — relaxing the shape rule must not relax that.
func TestValidateSstpDirectionStillRequiresIssAndAud(t *testing.T) {
	cases := []struct {
		name string
		dir  model.SstpDirection
		want string
	}{
		{"no iss", model.SstpDirection{
			Aud:  []string{"https://beta.example.com"},
			Mode: model.SstpModePublish,
		}, "primary.iss"},
		{"no aud", model.SstpDirection{
			Iss:  "https://alpha.example.com",
			Mode: model.SstpModePublish,
		}, "primary.aud"},
		{"empty aud entry", model.SstpDirection{
			Iss:  "https://alpha.example.com",
			Aud:  []string{""},
			Mode: model.SstpModePublish,
		}, "primary.aud"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSstpDirection("primary", tc.dir)
			if err == nil {
				t.Fatal("expected a refusal, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected the error to name %q, got %v", tc.want, err)
			}
		})
	}
}

func TestIsUriShaped(t *testing.T) {
	uris := []string{"https://a.example.com", "http://a.example.com", "urn:example:a", "spiffe://x/y"}
	for _, v := range uris {
		if !isUriShaped(v) {
			t.Errorf("%q should be URI-shaped", v)
		}
	}
	plain := []string{"alpha", "cluster.scim.example.com", "a b", ""}
	for _, v := range plain {
		if isUriShaped(v) {
			t.Errorf("%q should not be URI-shaped", v)
		}
	}
}
