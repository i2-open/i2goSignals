package goSetSstp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHTTPShapeConstants pins the on-wire HTTP shape the runner and route will key off later:
// path /sstp/{id}, POST, strict application/sstp+json.
func TestHTTPShapeConstants(t *testing.T) {
	assert.Equal(t, "/sstp/{id}", PathTemplate)
	assert.Equal(t, http.MethodPost, Method)
	assert.Equal(t, "application/sstp+json", ContentType)
}
