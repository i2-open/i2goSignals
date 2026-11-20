package memory

import (
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/daotest"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

func TestEventDAOMemory_DeliveriesParity(t *testing.T) {
	daotest.Deliveries(t, func(*testing.T) interfaces.EventDAO { return NewEventDAO() })
}
