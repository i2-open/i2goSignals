package delivery

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/stretchr/testify/assert"
)

func TestMemoryAdapter_ReturnsScriptedClassification(t *testing.T) {
	want := PushOutcome{
		Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
		RemoteAddress:  "10.0.0.1:443",
	}
	adapter := NewMemoryAdapter(want)

	got := adapter.Deliver(context.Background(), PushRequest{})

	assert.Equal(t, want.Classification, got.Classification)
	assert.Equal(t, want.RemoteAddress, got.RemoteAddress)
	assert.Equal(t, 1, adapter.Calls())
}
