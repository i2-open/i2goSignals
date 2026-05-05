package goSetPush

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClassifyResult_Accepted(t *testing.T) {
	c := ClassifyResult(PushResult{Accepted: true, StatusCode: http.StatusAccepted})
	assert.Equal(t, ClassAccepted, c.Class)
	assert.Equal(t, "Accepted", c.Class.String())
}

func TestClassifyResult_Transport(t *testing.T) {
	c := ClassifyResult(PushResult{Err: errors.New("dial tcp: connection refused"), StatusCode: 0})
	assert.Equal(t, ClassTransport, c.Class)
}

func TestClassifyResult_ServerError(t *testing.T) {
	for _, status := range []int{500, 502, 504} {
		c := ClassifyResult(PushResult{StatusCode: status, Err: errors.New("server error")})
		assert.Equal(t, ClassServerError, c.Class, "status=%d", status)
	}
}

func TestClassifyResult_503WithRetryAfterIsRateLimited(t *testing.T) {
	c := ClassifyResult(PushResult{
		StatusCode: http.StatusServiceUnavailable,
		Err:        errors.New("temporarily unavailable"),
		RetryAfter: 30 * time.Second,
	})
	assert.Equal(t, ClassRateLimited, c.Class, "503 + Retry-After should be peer back-pressure, not transport-bounded")
	assert.Equal(t, 30*time.Second, c.NextDelay)
}

func TestClassifyResult_503WithoutRetryAfterIsServerError(t *testing.T) {
	c := ClassifyResult(PushResult{
		StatusCode: http.StatusServiceUnavailable,
		Err:        errors.New("temporarily unavailable"),
	})
	assert.Equal(t, ClassServerError, c.Class)
}

func TestClassifyResult_Unauthorized(t *testing.T) {
	c := ClassifyResult(PushResult{StatusCode: http.StatusUnauthorized, Err: errors.New("auth failed")})
	assert.Equal(t, ClassUnauthorized, c.Class)
}

func TestClassifyResult_Forbidden(t *testing.T) {
	c := ClassifyResult(PushResult{StatusCode: http.StatusForbidden, Err: errors.New("forbidden")})
	assert.Equal(t, ClassForbidden, c.Class)
}

func TestClassifyResult_RateLimited(t *testing.T) {
	c := ClassifyResult(PushResult{
		StatusCode: http.StatusTooManyRequests,
		Err:        errors.New("rate limited"),
		RetryAfter: 60 * time.Second,
	})
	assert.Equal(t, ClassRateLimited, c.Class)
	assert.Equal(t, 60*time.Second, c.NextDelay)
}

func TestClassifyResult_RFC8935Error(t *testing.T) {
	for _, code := range []string{
		ErrInvalidAudience,
		ErrInvalidIssuer,
		ErrInvalidKey,
		ErrJwsSignatureFailed,
		ErrJweDecryptionFailed,
		ErrAccessDenied,
		ErrAuthenticationFailed,
		ErrInvalidRequest,
	} {
		c := ClassifyResult(PushResult{
			StatusCode: http.StatusBadRequest,
			Err:        &DeliveryErr{ErrCode: code, Description: "test"},
		})
		assert.Equal(t, ClassRFC8935Error, c.Class, "code=%s", code)
		assert.Equal(t, code, c.RFC8935ErrCode)
		assert.Equal(t, "test", c.RFC8935Description)
	}
}

func TestClassifyResult_400WithoutParseableBodyIsWeird(t *testing.T) {
	c := ClassifyResult(PushResult{
		StatusCode: http.StatusBadRequest,
		Err:        errors.New("RFC8935: unable to parse error response: EOF"),
	})
	assert.Equal(t, ClassWeirdResponse, c.Class)
}

func TestClassifyResult_WeirdClientError(t *testing.T) {
	for _, status := range []int{404, 410, 422} {
		c := ClassifyResult(PushResult{StatusCode: status, Err: errors.New("client error")})
		assert.Equal(t, ClassWeirdClientError, c.Class, "status=%d", status)
	}
}

func TestClassifyResult_WeirdResponseFor200(t *testing.T) {
	c := ClassifyResult(PushResult{StatusCode: http.StatusOK, Err: errors.New("unexpected 200")})
	assert.Equal(t, ClassWeirdResponse, c.Class)
}

func TestParseRetryAfter_DeltaSeconds(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, 30*time.Second, ParseRetryAfter("30", now))
	assert.Equal(t, time.Duration(0), ParseRetryAfter("0", now))
	assert.Equal(t, time.Duration(0), ParseRetryAfter("-5", now))
}

func TestParseRetryAfter_HTTPDate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	future := now.Add(45 * time.Second).UTC().Format(http.TimeFormat)
	got := ParseRetryAfter(future, now)
	// Allow a 1s tolerance (HTTP date is second-precision).
	assert.InDelta(t, float64(45*time.Second), float64(got), float64(time.Second))
}

func TestParseRetryAfter_PastDate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-1 * time.Hour).UTC().Format(http.TimeFormat)
	assert.Equal(t, time.Duration(0), ParseRetryAfter(past, now))
}

func TestParseRetryAfter_Empty(t *testing.T) {
	assert.Equal(t, time.Duration(0), ParseRetryAfter("", time.Now()))
	assert.Equal(t, time.Duration(0), ParseRetryAfter("garbage", time.Now()))
}

func TestPushSET_RetryAfterHonored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	result := PushSET(context.Background(), "test-set", TransmitterConfig{EndpointURL: server.URL})
	assert.False(t, result.Accepted)
	assert.Equal(t, http.StatusTooManyRequests, result.StatusCode)
	assert.Equal(t, 30*time.Second, result.RetryAfter)

	c := ClassifyResult(result)
	assert.Equal(t, ClassRateLimited, c.Class)
	assert.Equal(t, 30*time.Second, c.NextDelay)
}

func TestPushSET_RetryAfter503ParsedAsRateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	result := PushSET(context.Background(), "test-set", TransmitterConfig{EndpointURL: server.URL})
	c := ClassifyResult(result)
	assert.Equal(t, ClassRateLimited, c.Class)
	assert.Equal(t, 5*time.Second, c.NextDelay)
}

// Compile-time guard: every FailureClass enum value must produce a non-empty String() label so that
// no future enum extension silently produces "Unknown" labels in metrics or logs.
func TestFailureClass_StringCoversAllValues(t *testing.T) {
	for c := ClassAccepted; c <= ClassWeirdResponse; c++ {
		s := c.String()
		assert.NotEmpty(t, s)
		assert.NotEqual(t, "Unknown", s, "FailureClass(%d) has no String()", int(c))
	}
}

// Verify the suspicious 1xx/3xx case — an unexpected 200 OK comes back as WeirdResponse so the
// recovery state machine disables the stream rather than silently treating non-202 as success.
func TestClassifyResult_200OkNotAccepted(t *testing.T) {
	c := ClassifyResult(PushResult{
		StatusCode: http.StatusOK,
		Err:        fmt.Errorf("unexpected 200"),
		Accepted:   false,
	})
	assert.Equal(t, ClassWeirdResponse, c.Class)
}
