package auditexport

import (
	"context"
	"fmt"
	"sync"
)

// BusPublisher is the message-bus seam (Kafka, NATS, Pub/Sub). The core ships
// the interface and the backend wrapper; a concrete client registers itself
// with RegisterBusPublisher from its own package so the daemon does not take
// a broker dependency it may never use.
type BusPublisher interface {
	// Publish sends one batch; key is the batch id for partitioning/dedupe.
	Publish(ctx context.Context, topic, key string, payload []byte) error
	Close() error
}

// BusPublisherFactory builds a publisher from bus configuration.
type BusPublisherFactory func(cfg BusConfig) (BusPublisher, error)

var busFactory struct {
	mu sync.RWMutex
	f  BusPublisherFactory
}

// RegisterBusPublisher installs the concrete bus implementation.
func RegisterBusPublisher(f BusPublisherFactory) {
	busFactory.mu.Lock()
	defer busFactory.mu.Unlock()
	busFactory.f = f
}

type busBackend struct {
	topic string
	pub   BusPublisher
	h     *health
}

func init() {
	Register(BackendBus, func(cfg Config) (Backend, error) {
		busFactory.mu.RLock()
		f := busFactory.f
		busFactory.mu.RUnlock()
		if f == nil {
			return nil, fmt.Errorf("%w: bus (no BusPublisher registered; link a broker client that calls auditexport.RegisterBusPublisher)", ErrNotImplemented)
		}
		pub, err := f(cfg.Bus)
		if err != nil {
			return nil, err
		}
		return &busBackend{topic: cfg.Bus.Topic, pub: pub, h: newHealth(BackendBus)}, nil
	})
}

func (b *busBackend) Name() string { return BackendBus }

func (b *busBackend) Export(ctx context.Context, batch Batch) error {
	if err := b.pub.Publish(ctx, b.topic, batch.BatchID, EncodeNDJSON(batch)); err != nil {
		return b.h.markErr(Temporary(err))
	}
	b.h.markOK(len(batch.Events))
	return nil
}

func (b *busBackend) Healthy(context.Context) error { return b.h.Healthy() }

func (b *busBackend) Close() error { return b.pub.Close() }
