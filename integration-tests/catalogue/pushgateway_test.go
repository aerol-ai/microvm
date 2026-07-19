package catalogue

import "testing"

func TestFormatPercentileGauges(t *testing.T) {
	body := FormatPercentileGauges("aerolvm_bench_create", "wasm", 22, 40, 80)
	if !contains(body, `runtime="wasm"`) || !contains(body, "_p50_ms") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestPushgatewayURLUnset(t *testing.T) {
	t.Setenv("AEROL_PUSHGATEWAY_URL", "")
	if err := PushText("job", "inst", "a 1\n"); err != nil {
		t.Fatal(err)
	}
}
