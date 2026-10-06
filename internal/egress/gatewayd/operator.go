package gatewayd

import (
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// fromOperatorFile builds the dial guard and the upstream chain. Without an
// operator file the guard is the zero value (the container-gateway posture,
// §5.5) and there is no upstream. The private-cloud operator file (§5.10)
// adds the internal zone, the deny floor and the upstream proxy; an upstream
// whose credentials can't be read stops the gateway rather than sending
// requests without them.
func fromOperatorFile(path string) (egresspolicy.DialGuard, *egresspolicy.Upstream, error) {
	if path == "" {
		return egresspolicy.DialGuard{}, nil, nil
	}
	op, err := operator.Load(path)
	if err != nil {
		return egresspolicy.DialGuard{}, nil, err
	}
	up, err := op.UpstreamDialer()
	if err != nil {
		return egresspolicy.DialGuard{}, nil, err
	}
	return op.Guard(), up, nil
}
