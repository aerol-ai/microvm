package dockerpool

import (
	"testing"
)

func TestRecordAdoptMSNilReceiver(t *testing.T) {
	var m *Metrics
	m.RecordAdoptMS(12)
}
