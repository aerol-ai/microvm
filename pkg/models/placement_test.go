package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestValidateLabelKey(t *testing.T) {
	tests := []struct {
		key     string
		wantErr bool
	}{
		{key: "zone"},
		{key: "gpu"},
		{key: "tier.level"},
		{key: "a_b-c.d"},
		{key: "example.com/tier"},
		{key: "Z9"},
		{key: "", wantErr: true},
		{key: "-lead", wantErr: true},
		{key: "trail-", wantErr: true},
		{key: "has space", wantErr: true},
		{key: "Bad.Prefix/tier", wantErr: true},
		{key: "example.com/", wantErr: true},
		{key: "/tier", wantErr: true},
		{key: strings.Repeat("a", MaxLabelLength)},
		{key: strings.Repeat("a", MaxLabelLength+1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := ValidateLabelKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateLabelKey(%q) = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidPlacement) {
				t.Fatalf("error %v does not wrap ErrInvalidPlacement", err)
			}
		})
	}
}

func TestValidateLabelValue(t *testing.T) {
	tests := []struct {
		value   string
		wantErr bool
	}{
		{value: ""},
		{value: "eu-west-1a"},
		{value: "a10"},
		{value: "x_y.z"},
		{value: "-x", wantErr: true},
		{value: "x/y", wantErr: true},
		{value: "x y", wantErr: true},
		{value: strings.Repeat("v", MaxLabelLength)},
		{value: strings.Repeat("v", MaxLabelLength+1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if err := ValidateLabelValue("k", tt.value); (err != nil) != tt.wantErr {
				t.Fatalf("ValidateLabelValue(%q) = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestParseNodeLabels(t *testing.T) {
	tooMany := make([]string, 0, MaxNodeLabels+1)
	for i := range MaxNodeLabels + 1 {
		tooMany = append(tooMany, fmt.Sprintf("k%d=v", i))
	}
	tests := []struct {
		name    string
		raw     string
		zone    string
		want    map[string]string
		wantErr string
	}{
		{name: "nothing set", want: nil},
		{name: "zone only", zone: "eu-west-1a", want: map[string]string{"zone": "eu-west-1a"}},
		{name: "labels only", raw: "gpu=a10,tier=pci", want: map[string]string{"gpu": "a10", "tier": "pci"}},
		{name: "spaces trimmed", raw: " gpu = a10 , tier=pci ", want: map[string]string{"gpu": "a10", "tier": "pci"}},
		{name: "zone both ways agrees", raw: "zone=z1", zone: "z1", want: map[string]string{"zone": "z1"}},
		{name: "empty value allowed", raw: "spot=", want: map[string]string{"spot": ""}},
		{name: "same key same value twice", raw: "a=1,a=1", want: map[string]string{"a": "1"}},
		{name: "zone disagrees", raw: "zone=z1", zone: "z2", wantErr: "disagrees"},
		{name: "duplicate key", raw: "a=1,a=2", wantErr: "twice"},
		{name: "stray comma", raw: "a=1,,b=2", wantErr: "empty entry"},
		{name: "missing equals", raw: "gpu", wantErr: "not key=value"},
		{name: "bad key", raw: "-x=1", wantErr: "label key"},
		{name: "bad value", raw: "x=a b", wantErr: "value"},
		{name: "too many", raw: strings.Join(tooMany, ","), wantErr: "at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNodeLabels(tt.raw, tt.zone)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !errors.Is(err, ErrInvalidPlacement) {
					t.Fatalf("ParseNodeLabels(%q, %q) err = %v, want containing %q", tt.raw, tt.zone, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNodeLabels: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseNodeLabels = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizePlacementRule(t *testing.T) {
	tests := []struct {
		name    string
		in      *PlacementRule
		want    *PlacementRule
		wantErr string
	}{
		{name: "nil", in: nil, want: nil},
		{name: "empty is no rule", in: &PlacementRule{}, want: nil},
		{name: "blank zone is no rule", in: &PlacementRule{Zone: "  "}, want: nil},
		{name: "zone", in: &PlacementRule{Zone: " z1 "}, want: &PlacementRule{Zone: "z1"}},
		{name: "labels", in: &PlacementRule{Labels: map[string]string{"gpu": "a10"}}, want: &PlacementRule{Labels: map[string]string{"gpu": "a10"}}},
		{name: "zone given as a label moves to Zone", in: &PlacementRule{Labels: map[string]string{"zone": "z1", "gpu": "a10"}},
			want: &PlacementRule{Zone: "z1", Labels: map[string]string{"gpu": "a10"}}},
		{name: "zone both ways agrees", in: &PlacementRule{Zone: "z1", Labels: map[string]string{"zone": "z1"}}, want: &PlacementRule{Zone: "z1"}},
		{name: "zone both ways disagrees", in: &PlacementRule{Zone: "z1", Labels: map[string]string{"zone": "z2"}}, wantErr: "disagrees"},
		{name: "bad zone", in: &PlacementRule{Zone: "z 1"}, wantErr: "value"},
		{name: "bad key", in: &PlacementRule{Labels: map[string]string{"bad key": "v"}}, wantErr: "label key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizePlacementRule(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizePlacementRule: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// The zone counts toward the label cap: a rule of 16 labels plus a zone is
// one label more than any node can declare, so it is refused up front.
func TestNormalizePlacementRuleCapIncludesZone(t *testing.T) {
	labels := map[string]string{}
	for i := range MaxNodeLabels {
		labels[fmt.Sprintf("k%d", i)] = "v"
	}
	if _, err := NormalizePlacementRule(&PlacementRule{Labels: labels}); err != nil {
		t.Fatalf("16 labels: %v", err)
	}
	if _, err := NormalizePlacementRule(&PlacementRule{Zone: "z", Labels: labels}); err == nil {
		t.Fatal("16 labels plus a zone was accepted")
	}
}

func TestRequiredLabelsAndSatisfy(t *testing.T) {
	var none *PlacementRule
	if none.RequiredLabels() != nil || (&PlacementRule{}).RequiredLabels() != nil {
		t.Fatal("an empty rule must require nothing")
	}
	rule := &PlacementRule{Zone: "z1", Labels: map[string]string{"gpu": "a10"}}
	want := rule.RequiredLabels()
	if !reflect.DeepEqual(want, map[string]string{"zone": "z1", "gpu": "a10"}) {
		t.Fatalf("RequiredLabels = %v", want)
	}
	tests := []struct {
		name string
		have map[string]string
		ok   bool
	}{
		{name: "exact", have: map[string]string{"zone": "z1", "gpu": "a10"}, ok: true},
		{name: "superset", have: map[string]string{"zone": "z1", "gpu": "a10", "tier": "pci"}, ok: true},
		{name: "wrong zone", have: map[string]string{"zone": "z2", "gpu": "a10"}},
		{name: "missing label", have: map[string]string{"zone": "z1"}},
		{name: "unlabelled node", have: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LabelsSatisfy(tt.have, want); got != tt.ok {
				t.Fatalf("LabelsSatisfy(%v) = %v, want %v", tt.have, got, tt.ok)
			}
		})
	}
	if !LabelsSatisfy(nil, nil) {
		t.Fatal("no rule must be satisfied by an unlabelled node")
	}
}

func TestPlacementUnsatisfiableErrorNamesTheRule(t *testing.T) {
	err := PlacementUnsatisfiableError(map[string]string{"zone": "z1", "gpu": "a10"})
	if !errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("%v does not wrap ErrPlacementUnsatisfiable", err)
	}
	if !strings.Contains(err.Error(), "gpu=a10, zone=z1") {
		t.Fatalf("message %q does not name the rule in key order", err)
	}
	if CloneLabels(nil) != nil {
		t.Fatal("CloneLabels(nil) != nil")
	}
	src := map[string]string{"a": "1"}
	cp := CloneLabels(src)
	cp["a"] = "2"
	if src["a"] != "1" {
		t.Fatal("CloneLabels shares the map")
	}
}

// The rule must survive the JSON round trip the cluster spec takes (the
// router marshals the normalized request into the forwarded body and the
// FSM stores it as JSON).
func TestCreateSandboxRequestPlacementJSON(t *testing.T) {
	in := CreateSandboxRequest{Image: "alpine", Placement: &PlacementRule{Zone: "z1", Labels: map[string]string{"gpu": "a10"}}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"placement":{"zone":"z1","labels":{"gpu":"a10"}}`) {
		t.Fatalf("wire form %s", b)
	}
	var out CreateSandboxRequest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.Placement, in.Placement) {
		t.Fatalf("round trip %+v", out.Placement)
	}
	b, _ = json.Marshal(CreateSandboxRequest{Image: "alpine"})
	if strings.Contains(string(b), "placement") {
		t.Fatalf("a create without a rule must not carry the field: %s", b)
	}
}
