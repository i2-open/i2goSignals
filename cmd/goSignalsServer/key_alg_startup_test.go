package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartupRejectsInvalidKeyAlg runs main in a child process with an
// unsupported I2SIG_KEY_ALG: startup fails before anything else, with an error
// naming the variable (spec #114).
func TestStartupRejectsInvalidKeyAlg(t *testing.T) {
	if os.Getenv("I2SIG_TEST_RUN_MAIN") == "1" {
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartupRejectsInvalidKeyAlg$")
	cmd.Env = append(os.Environ(), "I2SIG_TEST_RUN_MAIN=1", "I2SIG_KEY_ALG=HS256", "MONGO_URL=")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "startup must fail; output: %s", out.String())
	assert.NotZero(t, exitErr.ExitCode())
	assert.Contains(t, out.String(), "I2SIG_KEY_ALG")
	assert.Contains(t, out.String(), "HS256")
}
