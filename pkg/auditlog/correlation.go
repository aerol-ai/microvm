package auditlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// The correlation id ties every record one API call produces together,
// across nodes: the API edge attaches it to the request context, the
// service layer stamps it on the records it writes, and the cluster forward
// helper sends it to peers as X-Correlation-ID (plans/identity-and-access.md
// §5.8, H3). It lives here, beside the record it fills, because the API,
// the service layer and the cluster package all need the one key and none
// of them may import the others.

type correlationKey struct{}

// ContextWithCorrelationID returns ctx carrying id. An empty id is a no-op,
// so a caller can pass a header value through without checking it.
func ContextWithCorrelationID(ctx context.Context, id string) context.Context {
	id = strings.TrimSpace(id)
	if ctx == nil || id == "" {
		return ctx
	}
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationIDFromContext returns the id ContextWithCorrelationID attached,
// or "".
func CorrelationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

// NewCorrelationID returns a fresh id: the wall clock, so ids sort roughly
// by time in a log, plus 64 random bits. If the entropy source fails the
// clock alone still yields a usable, if not unique, id: losing correlation
// must never cost a record.
func NewCorrelationID() string {
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return now
	}
	return now + "-" + hex.EncodeToString(b[:])
}
