package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripQuotes(t *testing.T) {
	// Test double quotes
	result := stripQuotes(`"test value"`)
	assert.Equal(t, "test value", result, "Should strip double quotes")

	// Test single quotes
	result = stripQuotes(`'test value'`)
	assert.Equal(t, "test value", result, "Should strip single quotes")

	// Test no quotes
	result = stripQuotes("test value")
	assert.Equal(t, "test value", result, "Should not modify string without quotes")

	// Test empty string
	result = stripQuotes("")
	assert.Equal(t, "", result, "Should handle empty string")

	// Test single character
	result = stripQuotes("a")
	assert.Equal(t, "a", result, "Should not strip single character")

	// Test mismatched quotes
	result = stripQuotes(`"test'`)
	assert.Equal(t, `"test'`, result, "Should not strip mismatched quotes")

	// Test only opening quote
	result = stripQuotes(`"test`)
	assert.Equal(t, `"test`, result, "Should not strip only opening quote")

	// Test only closing quote
	result = stripQuotes(`test"`)
	assert.Equal(t, `test"`, result, "Should not strip only closing quote")

	// Test quotes in middle
	result = stripQuotes(`test"value"test`)
	assert.Equal(t, `test"value"test`, result, "Should not strip quotes in middle")

	// Test port number with quotes (common Docker env var usage)
	result = stripQuotes(`"8888"`)
	assert.Equal(t, "8888", result, "Should strip quotes from port number")

	// Test URL with quotes (common Docker env var usage)
	result = stripQuotes(`"mongodb://root:dockTest@mongo1:30001"`)
	assert.Equal(t, "mongodb://root:dockTest@mongo1:30001", result, "Should strip quotes from MongoDB URL")

	// Test database name with quotes
	result = stripQuotes(`'goSignals1'`)
	assert.Equal(t, "goSignals1", result, "Should strip quotes from database name")

	// Test base URL with quotes
	result = stripQuotes(`"http://goSignals1:8888/"`)
	assert.Equal(t, "http://goSignals1:8888/", result, "Should strip quotes from base URL")

	// Test directory path with quotes
	result = stripQuotes(`"/path/to/adminUI"`)
	assert.Equal(t, "/path/to/adminUI", result, "Should strip quotes from directory path")
}
