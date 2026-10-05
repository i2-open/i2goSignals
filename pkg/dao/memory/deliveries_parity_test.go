package memory

import (
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/daotest"
)

func TestEventDAOMemory_DeliveriesParity(t *testing.T) {
	daotest.Deliveries(t, func(*testing.T) interfaces.EventDAO { return NewEventDAO() })
}
