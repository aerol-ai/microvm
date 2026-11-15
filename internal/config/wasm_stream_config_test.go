package config

import (
	"reflect"
	"testing"
	"time"
)

func TestWasmCodeRunModules(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		standard map[string]string
		want     map[string]string
	}{
		{
			name:     "derived from python, javascript and ruby",
			standard: map[string]string{"python": "python-3.12.0.wasm", "javascript": "qjs-wasi.wasm", "ruby": "ruby.wasm", "php": "php-cgi.wasm"},
			want: map[string]string{
				"python": "python", "python3": "python", "py": "python",
				"javascript": "javascript", "js": "javascript", "node": "javascript",
				"ruby": "ruby", "rb": "ruby",
			},
		},
		{
			name:     "a later alias stands in when the first is missing",
			standard: map[string]string{"quickjs": "qjs.wasm"},
			want:     map[string]string{"javascript": "quickjs", "js": "quickjs", "node": "quickjs"},
		},
		{
			name:     "no standard modules, no code-run",
			standard: map[string]string{},
			want:     map[string]string{},
		},
		{
			name:     "explicit setting wins and is parsed like the standard modules",
			raw:      " Python = mypy , bad, js=quickjs",
			standard: map[string]string{"python": "python.wasm", "ruby": "ruby.wasm"},
			want:     map[string]string{"python": "mypy", "js": "quickjs"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasmCodeRunModules(tc.raw, tc.standard); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestLoadWasmStreamSettings(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	t.Setenv("SB_WASM_STANDARD_MODULES", "python=python.wasm")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WasmMaxStreamsPerSandbox != 8 {
		t.Fatalf("default stream cap = %d, want 8", cfg.WasmMaxStreamsPerSandbox)
	}
	if cfg.WasmStreamMaxMessageBytes != 1<<20 {
		t.Fatalf("default stream message cap = %d, want 1 MiB", cfg.WasmStreamMaxMessageBytes)
	}
	if cfg.WasmInterpMaxContexts != 4 || cfg.WasmInterpIdleTTL != 15*time.Minute {
		t.Fatalf("interpreter defaults = %d contexts, idle %s", cfg.WasmInterpMaxContexts, cfg.WasmInterpIdleTTL)
	}
	if cfg.WasmCodeRunModules["py"] != "python" || cfg.WasmCodeRunModules["ruby"] != "" {
		t.Fatalf("derived code-run modules = %#v", cfg.WasmCodeRunModules)
	}

	t.Setenv("SB_WASM_MAX_STREAMS_PER_SANDBOX", "3")
	t.Setenv("SB_WASM_STREAM_MAX_MESSAGE_BYTES", "4096")
	t.Setenv("SB_WASM_CODERUN_MODULES", "ruby=ruby")
	t.Setenv("SB_WASM_INTERP_MAX_CONTEXTS", "2")
	t.Setenv("SB_WASM_INTERP_IDLE_TTL", "90s")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WasmInterpMaxContexts != 2 || cfg.WasmInterpIdleTTL != 90*time.Second {
		t.Fatalf("interpreter settings = %d contexts, idle %s", cfg.WasmInterpMaxContexts, cfg.WasmInterpIdleTTL)
	}
	if cfg.WasmStreamMaxMessageBytes != 4096 {
		t.Fatalf("stream message cap = %d", cfg.WasmStreamMaxMessageBytes)
	}
	if cfg.WasmMaxStreamsPerSandbox != 3 || !reflect.DeepEqual(cfg.WasmCodeRunModules, map[string]string{"ruby": "ruby"}) {
		t.Fatalf("cap %d modules %#v", cfg.WasmMaxStreamsPerSandbox, cfg.WasmCodeRunModules)
	}
}
