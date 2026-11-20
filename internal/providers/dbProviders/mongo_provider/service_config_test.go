package mongo_provider

import (
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestStreamServiceConfigFromEnv_EventValidation asserts the production wiring of
// I2SIG_STREAM_EVENT_VALIDATION in the mongo provider (spec #247 issue #250).
// The knob must be parsed in BOTH providers' service_config.go, so this mirrors
// the memory provider's test. A recognized value is parsed case-insensitively;
// an unset/empty/unrecognized value leaves the field unset so NewStreamService
// falls back to NONE with a WARN. No Mongo connection is required.
func TestStreamServiceConfigFromEnv_EventValidation(t *testing.T) {
	cases := map[string]model.EventValidationMode{
		"":        model.EventValidationUnset,
		"   ":     model.EventValidationUnset,
		"bogus":   model.EventValidationUnset,
		"NONE":    model.EventValidationNone,
		"warn":    model.EventValidationWarn,
		"ENFORCE": model.EventValidationEnforce,
		"Strict":  model.EventValidationStrict,
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Setenv("I2SIG_STREAM_EVENT_VALIDATION", in)
			cfg := streamServiceConfigFromEnv()
			if cfg.EventValidationDefault != want {
				t.Errorf("I2SIG_STREAM_EVENT_VALIDATION=%q gave EventValidationDefault %q, want %q",
					in, cfg.EventValidationDefault, want)
			}
		})
	}
}
