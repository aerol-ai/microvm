package release

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const testSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validMetadata() Metadata {
	return Metadata{
		Version:               "v0.6.12",
		UpgradeFromMin:        "v0.6.11",
		OneWayMigrations:      []int{13, 15},
		HostSetupSHA256:       testSHA,
		HostSetupNeedsNetwork: true,
		EgressGatewayProtocol: []int{1, 2},
		FSMOpsVersion:         10,
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Metadata)
	}{
		{name: "full", edit: func(*Metadata) {}},
		{name: "no one-way migrations", edit: func(m *Metadata) { m.OneWayMigrations = []int{} }},
		{name: "prerelease upgrading from itself", edit: func(m *Metadata) {
			m.Version, m.UpgradeFromMin, m.HostSetupNeedsNetwork = "v0.7.0-rc.1", "v0.7.0-rc.1", false
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := validMetadata()
			tt.edit(&want)
			data, err := Marshal(want)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !strings.HasSuffix(string(data), "}\n") {
				t.Fatalf("Marshal output does not end in a newline: %q", data)
			}
			got, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v\n%s", err, data)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip = %+v, want %+v", got, want)
			}
		})
	}
}

// The wire names are the contract with release.yml, aerolvm and older
// readers; renaming a Go field must not rename them.
func TestMarshalUsesThePlanFieldNames(t *testing.T) {
	m := validMetadata()
	m.OneWayMigrations = []int{}
	data, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{
  "version": "v0.6.12",
  "upgrade_from_min": "v0.6.11",
  "one_way_migrations": [],
  "host_setup_sha256": "` + testSHA + `",
  "host_setup_needs_network": true,
  "egress_gateway_protocol": [
    1,
    2
  ],
  "fsm_ops_version": 10
}
`
	if string(data) != want {
		t.Fatalf("Marshal =\n%s\nwant\n%s", data, want)
	}
}

func TestParseIgnoresUnknownFields(t *testing.T) {
	data, err := Marshal(validMetadata())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	newer := strings.Replace(string(data), `"fsm_ops_version"`, `"field_from_a_newer_release": {"x": 1}, "fsm_ops_version"`, 1)
	got, err := Parse([]byte(newer))
	if err != nil {
		t.Fatalf("Parse with an unknown field: %v", err)
	}
	if !reflect.DeepEqual(got, validMetadata()) {
		t.Fatalf("Parse = %+v, want %+v", got, validMetadata())
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(*Metadata)
		wantErr string
	}{
		{"valid", func(*Metadata) {}, ""},
		{"bad version", func(m *Metadata) { m.Version = "0.6.12" }, "version"},
		{"bad upgrade_from_min", func(m *Metadata) { m.UpgradeFromMin = "latest" }, "upgrade_from_min"},
		{"upgrade_from_min newer than version", func(m *Metadata) { m.UpgradeFromMin = "v0.7.0" }, "newer than version"},
		{"missing one_way_migrations", func(m *Metadata) { m.OneWayMigrations = nil }, "one_way_migrations is missing"},
		{"zero migration number", func(m *Metadata) { m.OneWayMigrations = []int{0} }, "not positive"},
		{"unsorted migrations", func(m *Metadata) { m.OneWayMigrations = []int{15, 13} }, "strictly ascending"},
		{"duplicate migrations", func(m *Metadata) { m.OneWayMigrations = []int{13, 13} }, "strictly ascending"},
		{"short sha", func(m *Metadata) { m.HostSetupSHA256 = "abc" }, "host_setup_sha256"},
		{"uppercase sha", func(m *Metadata) { m.HostSetupSHA256 = strings.ToUpper(testSHA) }, "host_setup_sha256"},
		{"no gateway protocol", func(m *Metadata) { m.EgressGatewayProtocol = nil }, "egress_gateway_protocol is empty"},
		{"negative gateway protocol", func(m *Metadata) { m.EgressGatewayProtocol = []int{-1} }, "not positive"},
		{"unsorted gateway protocol", func(m *Metadata) { m.EgressGatewayProtocol = []int{2, 1} }, "strictly ascending"},
		{"zero fsm ops version", func(m *Metadata) { m.FSMOpsVersion = 0 }, "fsm_ops_version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validMetadata()
			tt.edit(&m)
			err := m.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate = %v, want an error containing %q", err, tt.wantErr)
			}
			if _, err := Marshal(m); err == nil {
				t.Fatal("Marshal accepted invalid metadata")
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name, data, wantErr string
	}{
		{"not json", `{`, "decode"},
		{"wrong type", `{"version": 12}`, "decode"},
		{"empty object", `{}`, "version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.data)); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestUpgradeAllowedFrom(t *testing.T) {
	m := validMetadata() // v0.6.12, upgrade_from_min v0.6.11
	tests := []struct {
		current string
		wantErr string
		tooOld  bool
	}{
		{current: "v0.6.11"},
		{current: "v0.6.12"},
		{current: "v0.7.0"}, // a downgrade is not this check's business
		{current: "v0.6.10", wantErr: "upgrade to v0.6.11 or later first", tooOld: true},
		{current: "v0.6.11-rc.1", wantErr: "cannot upgrade straight", tooOld: true},
		{current: "dev", wantErr: "current version"},
	}
	for _, tt := range tests {
		t.Run(tt.current, func(t *testing.T) {
			err := m.UpgradeAllowedFrom(tt.current)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("UpgradeAllowedFrom(%s) = %v, want nil", tt.current, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("UpgradeAllowedFrom(%s) = %v, want %q", tt.current, err, tt.wantErr)
			}
			if errors.Is(err, ErrUpgradeFromTooOld) != tt.tooOld {
				t.Fatalf("errors.Is(ErrUpgradeFromTooOld) = %v, want %v", !tt.tooOld, tt.tooOld)
			}
		})
	}

	bad := validMetadata()
	bad.UpgradeFromMin = "nope"
	if err := bad.UpgradeAllowedFrom("v0.6.11"); err == nil || !strings.Contains(err.Error(), "upgrade_from_min") {
		t.Fatalf("UpgradeAllowedFrom with a malformed floor = %v", err)
	}
}
