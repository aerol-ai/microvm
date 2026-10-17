package identity

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

var testNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// mint returns a fresh token and its record for team and role.
func mint(t testing.TB, name, team string, role controlplane.Role) (identitywire.APIToken, TokenRecord) {
	t.Helper()
	tok, err := identitywire.NewAPIToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := tok.SecretHash()
	return tok, TokenRecord{
		ID: tok.ID, Name: name, Role: role, OwnerRef: OwnerRefForTeam(team), CreatedBy: "operator",
		CreatedAt: testNow, ExpiresAt: testNow.Add(24 * time.Hour), SecretHash: hash[:],
	}
}

func TestTokenRecordValidate(t *testing.T) {
	_, good := mint(t, "ci-deploy", "payments", controlplane.RoleRunner)
	_, fleetAdmin := mint(t, "root", controlplane.FleetTeam, controlplane.RoleAdmin)
	cases := []struct {
		name   string
		mutate func(*TokenRecord)
		ok     bool
	}{
		{"valid team runner", func(*TokenRecord) {}, true},
		{"bad id", func(r *TokenRecord) { r.ID = "tok_x" }, false},
		{"bad name", func(r *TokenRecord) { r.Name = "has space" }, false},
		{"bad role", func(r *TokenRecord) { r.Role = "owner" }, false},
		{"short hash", func(r *TokenRecord) { r.SecretHash = r.SecretHash[:16] }, false},
		{"no expiry", func(r *TokenRecord) { r.ExpiresAt = time.Time{} }, false},
		{"bad team", func(r *TokenRecord) { r.OwnerRef = "team:Bad_Team" }, false},
		{"foreign owner", func(r *TokenRecord) { r.OwnerRef = "acct-1" }, false},
		{"auditor on one team", func(r *TokenRecord) { r.Role = controlplane.RoleAuditor }, false},
	}
	for _, tc := range cases {
		rec := good.Clone()
		tc.mutate(&rec)
		err := rec.Validate()
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrInvalidTokenRecord)) {
			t.Errorf("%s: Validate = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	if err := fleetAdmin.Validate(); err != nil {
		t.Fatalf("a fleet admin token is valid: %v", err)
	}
}

func TestTokenRecordViews(t *testing.T) {
	_, team := mint(t, "ci", "payments", controlplane.RoleRunner)
	_, fleet := mint(t, "scrape", controlplane.FleetTeam, controlplane.RoleViewer)
	if team.Team() != "payments" || fleet.Team() != controlplane.FleetTeam || (TokenRecord{OwnerRef: "acct"}).Team() != "acct" {
		t.Fatalf("Team: %q %q", team.Team(), fleet.Team())
	}
	if team.NameKey() == fleet.NameKey() || !strings.HasPrefix(team.NameKey(), "team:payments\x00") {
		t.Fatalf("name keys: %q %q", team.NameKey(), fleet.NameKey())
	}
	if team.Expired(testNow) || !team.Expired(team.ExpiresAt) || !team.Expired(team.ExpiresAt.Add(time.Second)) {
		t.Fatal("expiry is exclusive of ExpiresAt")
	}
	a := team.Access()
	if a.Principal.Kind != controlplane.PrincipalToken || a.Principal.ID != team.ID || a.Principal.Name != "ci" ||
		a.Role != controlplane.RoleRunner || a.Fleet || a.Identity.OwnerRef != "team:payments" || !a.ExpiresAt.Equal(team.ExpiresAt) {
		t.Fatalf("team access = %+v", a)
	}
	if fa := fleet.Access(); !fa.Fleet || fa.Identity.OwnerRef != "" || fa.Team() != controlplane.FleetTeam {
		t.Fatalf("fleet access = %+v", fa)
	}
	clone := team.Clone()
	clone.SecretHash[0] ^= 0xff
	if clone.SecretHash[0] == team.SecretHash[0] {
		t.Fatal("Clone must copy the hash")
	}
}

func TestSortTokenRecords(t *testing.T) {
	recs := []TokenRecord{
		{ID: "tok_3", Name: "b", OwnerRef: "team:x"},
		{ID: "tok_2", Name: "a", OwnerRef: "team:x"},
		{ID: "tok_1", Name: "z", OwnerRef: ""},
		{ID: "tok_0", Name: "a", OwnerRef: "team:x"},
	}
	SortTokenRecords(recs)
	var got []string
	for _, r := range recs {
		got = append(got, r.ID)
	}
	if strings.Join(got, ",") != "tok_1,tok_0,tok_2,tok_3" {
		t.Fatalf("order = %v", got)
	}
}

func TestTokenSet(t *testing.T) {
	var s TokenSet
	_, rec := mint(t, "ci", "payments", controlplane.RoleRunner)
	if _, found, fresh := s.LookupToken(rec.ID); found || !fresh {
		t.Fatal("an empty single-node set is fresh and finds nothing")
	}
	s.Put(rec)
	got, found, fresh := s.LookupToken(rec.ID)
	if !found || !fresh || got.Name != "ci" || s.Len() != 1 {
		t.Fatalf("after Put: %+v %v %v", got, found, fresh)
	}
	rec.SecretHash[0] ^= 0xff // the set keeps its own copy
	if got, _, _ := s.LookupToken(rec.ID); got.SecretHash[0] == rec.SecretHash[0] {
		t.Fatal("Put must copy the record")
	}
	s.Delete(rec.ID)
	s.Delete(rec.ID)
	if _, found, _ := s.LookupToken(rec.ID); found {
		t.Fatal("deleted")
	}
	_, a := mint(t, "a", "payments", controlplane.RoleViewer)
	_, b := mint(t, "b", "payments", controlplane.RoleViewer)
	s.Replace([]TokenRecord{a, b})
	if s.Len() != 2 {
		t.Fatalf("Replace: %d", s.Len())
	}
	// Concurrent readers and writers (run under -race).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); s.LookupToken(a.ID) }()
		go func() { defer wg.Done(); s.Put(b) }()
	}
	wg.Wait()
}
