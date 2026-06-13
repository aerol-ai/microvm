package harness

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// capsFile is the on-disk shape of scenarios/<name>.caps.yml.
//
//	name: single-node
//	capabilities: [docker, domain]
type capsFile struct {
	Name         string       `yaml:"name"`
	Capabilities []Capability `yaml:"capabilities"`
}

// Env var names the harness reads. run.sh exports these after provisioning.
const (
	EnvBaseURL  = "AEROL_BASE_URL" // e.g. https://abc.itest.example.com or http://localhost:21212
	EnvPAT      = "AEROL_PAT"
	EnvScenario = "AEROL_SCENARIO"
	EnvCaps     = "AEROL_CAPS"   // path to the scenario caps.yml
	EnvDomain   = "AEROL_DOMAIN" // leased apex domain; empty in local-mode
)

// LoadScenario builds a Scenario from the environment. It reads the caps file
// pointed at by AEROL_CAPS and the base URL + PAT from env. Returns an error
// (rather than skipping) when required env is missing so a misconfigured run
// fails loudly instead of silently testing nothing.
func LoadScenario() (*Scenario, error) {
	capsPath := os.Getenv(EnvCaps)
	if capsPath == "" {
		return nil, fmt.Errorf("%s not set (path to scenario caps.yml)", EnvCaps)
	}
	raw, err := os.ReadFile(capsPath)
	if err != nil {
		return nil, fmt.Errorf("read caps %s: %w", capsPath, err)
	}
	cf, err := parseCaps(raw)
	if err != nil {
		return nil, fmt.Errorf("parse caps %s: %w", capsPath, err)
	}

	base := strings.TrimRight(os.Getenv(EnvBaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("%s not set (deployment base URL)", EnvBaseURL)
	}
	pat := os.Getenv(EnvPAT)
	if pat == "" {
		return nil, fmt.Errorf("%s not set (PAT token)", EnvPAT)
	}

	name := os.Getenv(EnvScenario)
	if name == "" {
		name = cf.Name
	}

	caps := make(map[Capability]bool, len(cf.Capabilities))
	for _, c := range cf.Capabilities {
		caps[c] = true
	}
	return &Scenario{
		Name:    name,
		BaseURL: base,
		PAT:     pat,
		Domain:  os.Getenv(EnvDomain),
		caps:    caps,
	}, nil
}

// parseCaps is split out so skip_test.go can exercise capability parsing with
// no environment or filesystem.
func parseCaps(raw []byte) (capsFile, error) {
	var cf capsFile
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		return capsFile{}, err
	}
	return cf, nil
}
