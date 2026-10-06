package gatewayd

import (
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// guardFromOperatorFile builds the dial guard. Without an operator file it is
// the zero value: the container-gateway posture (§5.5). The private-cloud
// operator file (§5.10) adds the internal zone and the deny floor.
func guardFromOperatorFile(path string) (egresspolicy.DialGuard, error) {
	if path == "" {
		return egresspolicy.DialGuard{}, nil
	}
	op, err := operator.Load(path)
	if err != nil {
		return egresspolicy.DialGuard{}, err
	}
	return op.Guard(), nil
}
