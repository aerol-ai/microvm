package config

import (
	"strings"
	"testing"
	"time"
)

// fleetBaseEnv sets the minimum env for Load() to reach the fleet validation
// without tripping unrelated required-field checks.
func fleetBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
}

func TestFleetDisabledByDefault(t *testing.T) {
	fleetBaseEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FleetControlPlaneEnabled {
		t.Errorf("FleetControlPlaneEnabled = true, want false by default")
	}
}

func TestFleetEnabledRequiresEndpoint(t *testing.T) {
	fleetBaseEnv(t)
	t.Setenv("SB_FLEET_ENABLED", "true")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SB_FLEET_ENDPOINT") {
		t.Fatalf("err = %v, want SB_FLEET_ENDPOINT required", err)
	}
}

func TestFleetEnabledRejectsRelativeURL(t *testing.T) {
	fleetBaseEnv(t)
	t.Setenv("SB_FLEET_ENABLED", "true")
	t.Setenv("SB_FLEET_ENDPOINT", "fleet.aerol.ai")
	t.Setenv("SB_FLEET_TOKEN", "avm_x")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "absolute URL") {
		t.Fatalf("err = %v, want absolute URL error", err)
	}
}

func TestFleetEnabledRequiresToken(t *testing.T) {
	fleetBaseEnv(t)
	t.Setenv("SB_FLEET_ENABLED", "true")
	t.Setenv("SB_FLEET_ENDPOINT", "https://fleet.aerol.ai")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SB_FLEET_TOKEN") {
		t.Fatalf("err = %v, want SB_FLEET_TOKEN required", err)
	}
}

func TestFleetEnabledValid(t *testing.T) {
	fleetBaseEnv(t)
	t.Setenv("SB_FLEET_ENABLED", "true")
	t.Setenv("SB_FLEET_ENDPOINT", "https://fleet.aerol.ai")
	t.Setenv("SB_FLEET_TOKEN", "avm_abc123")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.FleetControlPlaneEnabled {
		t.Errorf("FleetControlPlaneEnabled = false, want true")
	}
	if cfg.FleetControlPlaneEndpoint != "https://fleet.aerol.ai" {
		t.Errorf("endpoint = %q", cfg.FleetControlPlaneEndpoint)
	}
	if cfg.FleetControlPlaneToken != "avm_abc123" {
		t.Errorf("token not loaded")
	}
	if cfg.FleetControlPlaneContractRefresh != 5*time.Minute {
		t.Errorf("contract refresh = %v, want default 5m", cfg.FleetControlPlaneContractRefresh)
	}
}
