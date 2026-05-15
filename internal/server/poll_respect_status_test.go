package server

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

// Slice #68 tracer: POLL_SRV_BEHAVIOR (string MODE/ALWAYSON) is replaced by
// I2SIG_POLL_RESPECT_STATUS (bool). envcompat.LookupWithTranslate must map
// the legacy values: MODE → true, ALWAYSON → false. The new name takes
// precedence; unset defaults to true (MODE was the previous default).

func TestLoadPollRespectStatus_UnsetDefaultsTrue(t *testing.T) {
    t.Setenv("I2SIG_POLL_RESPECT_STATUS", "")
    t.Setenv("POLL_SRV_BEHAVIOR", "")
    assert.True(t, loadPollRespectStatus())
}

func TestLoadPollRespectStatus_NewName_BoolValues(t *testing.T) {
    t.Setenv("POLL_SRV_BEHAVIOR", "")

    t.Setenv("I2SIG_POLL_RESPECT_STATUS", "true")
    assert.True(t, loadPollRespectStatus())

    t.Setenv("I2SIG_POLL_RESPECT_STATUS", "false")
    assert.False(t, loadPollRespectStatus())
}

func TestLoadPollRespectStatus_LegacyMode_TranslatesTrue(t *testing.T) {
    t.Setenv("I2SIG_POLL_RESPECT_STATUS", "")
    t.Setenv("POLL_SRV_BEHAVIOR", "MODE")
    assert.True(t, loadPollRespectStatus())
}

func TestLoadPollRespectStatus_LegacyAlwayson_TranslatesFalse(t *testing.T) {
    t.Setenv("I2SIG_POLL_RESPECT_STATUS", "")
    t.Setenv("POLL_SRV_BEHAVIOR", "ALWAYSON")
    assert.False(t, loadPollRespectStatus())
}

func TestLoadPollRespectStatus_NewNameWinsOverLegacy(t *testing.T) {
    t.Setenv("I2SIG_POLL_RESPECT_STATUS", "false")
    t.Setenv("POLL_SRV_BEHAVIOR", "MODE")
    assert.False(t, loadPollRespectStatus())
}
