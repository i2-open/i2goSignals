package goSetSstp

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestClassifyResult_Table walks the Q12.2 error class table: transport (no response),
// 4xx → request-level, 5xx → transient, 200-with-non-empty-setErrs → per-JTI, and the
// happy 200 with no per-JTI errors.
func TestClassifyResult_Table(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   FailureClass
	}{
		{
			name:   "transport failure, no HTTP response",
			result: Result{StatusCode: 0, Err: errors.New("dial tcp: connection refused")},
			want:   ClassTransport,
		},
		{
			name:   "200 OK, no per-JTI errors",
			result: Result{StatusCode: http.StatusOK},
			want:   ClassOK,
		},
		{
			name: "200 OK with empty setErrs map is still OK",
			result: Result{
				StatusCode: http.StatusOK,
				Message:    &Message{SetErrs: map[string]SetErr{}},
			},
			want: ClassOK,
		},
		{
			name: "200 OK with non-empty setErrs is per-JTI",
			result: Result{
				StatusCode: http.StatusOK,
				Message: &Message{SetErrs: map[string]SetErr{
					"jti-1": {Err: ErrJwtAud, Description: "bad aud"},
				}},
			},
			want: ClassPerJTI,
		},
		{
			name:   "400 Bad Request is request-level",
			result: Result{StatusCode: http.StatusBadRequest, Err: errors.New("unparseable")},
			want:   ClassRequestError,
		},
		{
			name:   "401 Unauthorized is request-level",
			result: Result{StatusCode: http.StatusUnauthorized},
			want:   ClassRequestError,
		},
		{
			name:   "403 Forbidden is request-level",
			result: Result{StatusCode: http.StatusForbidden},
			want:   ClassRequestError,
		},
		{
			name:   "404 Not Found (deleted pair) is request-level",
			result: Result{StatusCode: http.StatusNotFound},
			want:   ClassRequestError,
		},
		{
			name:   "415 Unsupported Media Type is request-level",
			result: Result{StatusCode: http.StatusUnsupportedMediaType},
			want:   ClassRequestError,
		},
		{
			name:   "429 Too Many Requests is request-level",
			result: Result{StatusCode: http.StatusTooManyRequests},
			want:   ClassRequestError,
		},
		{
			name:   "500 Internal Server Error is transient",
			result: Result{StatusCode: http.StatusInternalServerError},
			want:   ClassTransient,
		},
		{
			name:   "502 Bad Gateway is transient",
			result: Result{StatusCode: http.StatusBadGateway},
			want:   ClassTransient,
		},
		{
			name:   "503 Service Unavailable is transient",
			result: Result{StatusCode: http.StatusServiceUnavailable},
			want:   ClassTransient,
		},
		{
			name:   "504 Gateway Timeout is transient",
			result: Result{StatusCode: http.StatusGatewayTimeout},
			want:   ClassTransient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyResult(tt.result)
			assert.Equal(t, tt.want, c.Class, "status=%d", tt.result.StatusCode)
		})
	}
}

// TestClassifyResult_PerJTIErrorsSurfaced confirms the per-JTI errors are carried through to
// the caller so it can ack/log each failed jti.
func TestClassifyResult_PerJTIErrorsSurfaced(t *testing.T) {
	errs := map[string]SetErr{
		"jti-a": {Err: ErrJws, Description: "sig failed"},
		"jti-b": {Err: ErrSetType, Description: "unexpected type"},
	}
	c := ClassifyResult(Result{StatusCode: http.StatusOK, Message: &Message{SetErrs: errs}})
	assert.Equal(t, ClassPerJTI, c.Class)
	assert.Equal(t, errs, c.SetErrs)
}

// TestClassifyResult_NextDelayFromRetryAfter confirms Retry-After flows into NextDelay.
func TestClassifyResult_NextDelayFromRetryAfter(t *testing.T) {
	c := ClassifyResult(Result{
		StatusCode: http.StatusServiceUnavailable,
		RetryAfter: 30 * time.Second,
	})
	assert.Equal(t, ClassTransient, c.Class)
	assert.Equal(t, 30*time.Second, c.NextDelay)
}

// TestFailureClass_String pins the human-readable labels used for logs and metric labels.
func TestFailureClass_String(t *testing.T) {
	assert.Equal(t, "OK", ClassOK.String())
	assert.Equal(t, "Transport", ClassTransport.String())
	assert.Equal(t, "Transient", ClassTransient.String())
	assert.Equal(t, "RequestError", ClassRequestError.String())
	assert.Equal(t, "PerJTI", ClassPerJTI.String())
	assert.Equal(t, "WeirdResponse", ClassWeirdResponse.String())
}

// TestClassifyResult_WeirdResponse covers status codes outside the 2xx/4xx/5xx contract
// (e.g. 3xx) — treated as a misconfigured peer, parallel to goSetPush's ClassWeirdResponse.
func TestClassifyResult_WeirdResponse(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusContinue} {
		c := ClassifyResult(Result{StatusCode: status})
		assert.Equal(t, ClassWeirdResponse, c.Class, "status=%d", status)
	}
}
