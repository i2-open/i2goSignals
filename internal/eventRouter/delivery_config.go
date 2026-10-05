package eventRouter

import (
	"os"
	"strconv"
	"time"
)

const (
	// defaultDeliveryInFlightMax is the I2SIG_DELIVERY_INFLIGHT_MAX default:
	// twice the largest push batch the ADR 0037 ceiling allows (4 x 32), so
	// one full batch can be on the wire while the previous one's ack is
	// written. It is also the most SETs a crash can redeliver per stream.
	defaultDeliveryInFlightMax = 256
	// defaultAckCoalesceWindow is the I2SIG_ACK_COALESCE_WINDOW default.
	defaultAckCoalesceWindow = 5 * time.Millisecond
)

// deliveryInFlightMax resolves I2SIG_DELIVERY_INFLIGHT_MAX. An unset or
// invalid value gives the default.
func deliveryInFlightMax() int {
	if val := os.Getenv("I2SIG_DELIVERY_INFLIGHT_MAX"); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			return i
		}
		eventLogger.Warn("Ignoring invalid I2SIG_DELIVERY_INFLIGHT_MAX (want a positive integer)", "value", val)
	}
	return defaultDeliveryInFlightMax
}

// ackCoalesceWindow resolves I2SIG_ACK_COALESCE_WINDOW. 0 acks inline, as
// before #336. An unset or invalid value gives the default.
func ackCoalesceWindow() time.Duration {
	if val := os.Getenv("I2SIG_ACK_COALESCE_WINDOW"); val != "" {
		if d, err := time.ParseDuration(val); err == nil && d >= 0 {
			return d
		}
		eventLogger.Warn("Ignoring invalid I2SIG_ACK_COALESCE_WINDOW (want a non-negative duration)", "value", val)
	}
	return defaultAckCoalesceWindow
}
