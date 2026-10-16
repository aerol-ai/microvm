package service

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// The service keeps unexported mirrors of auditlog.ScanOptions and
// auditlog.ChainScan so its call sites read as they did before the chain
// scan moved. A field added to the shared types but not to a mirror would be
// silently dropped at the conversion, so the field lists are pinned here.
func TestSecretAuditChainScanMirrorsAuditlog(t *testing.T) {
	for _, pair := range []struct {
		shared, mirror reflect.Type
	}{
		{reflect.TypeOf(auditlog.ChainScan{}), reflect.TypeOf(secretAuditChainScan{})},
		{reflect.TypeOf(auditlog.ScanOptions{}), reflect.TypeOf(secretAuditScanOptions{})},
	} {
		if pair.shared.NumField() != pair.mirror.NumField() {
			t.Fatalf("%s has %d fields, mirror %s has %d", pair.shared, pair.shared.NumField(), pair.mirror, pair.mirror.NumField())
		}
		for i := 0; i < pair.shared.NumField(); i++ {
			s, m := pair.shared.Field(i), pair.mirror.Field(i)
			if !strings.EqualFold(s.Name, m.Name) || s.Type != m.Type {
				t.Fatalf("field %d: %s %s vs mirror %s %s", i, s.Name, s.Type, m.Name, m.Type)
			}
		}
	}

	full := auditlog.ChainScan{
		Head: "h", EventID: "e", LastLineStart: 1, Found: map[string]bool{"h": true},
		WitnessedThrough: "w", ValidEnd: 2, TornBytes: 3, MissingNewline: true, Records: 4, Redacted: 5,
	}
	got := reflect.ValueOf(secretAuditChainScanFrom(full))
	for i := 0; i < got.NumField(); i++ {
		if got.Field(i).IsZero() {
			t.Fatalf("secretAuditChainScanFrom dropped %s", got.Type().Field(i).Name)
		}
	}
}
