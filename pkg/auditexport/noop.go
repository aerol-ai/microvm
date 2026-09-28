package auditexport

import "context"

// noopBackend is the open-source default: evidence stays on local disk only,
// and the daemon says so at boot. Nothing is claimed beyond that.
type noopBackend struct{}

func init() {
	Register(BackendNoop, func(Config) (Backend, error) { return &noopBackend{}, nil })
}

func (*noopBackend) Name() string                        { return BackendNoop }
func (*noopBackend) Export(context.Context, Batch) error { return nil }
func (*noopBackend) Healthy(context.Context) error       { return nil }
