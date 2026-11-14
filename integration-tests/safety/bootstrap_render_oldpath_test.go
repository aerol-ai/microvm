package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// oldJoinPathRenders is the SHA-256 of each old-join-path render of the
// fixture (testdata/bootstrap_render/main.tf, one_line_join = false) made
// with v0.6.13's Terraform/templates/bootstrap.sh.tftpl.
//
// Every node uses user_data_replace_on_change (Terraform/nodes.tf), and the
// whole rendered script is its user_data, comments included. So any byte the
// template adds to the old join path makes the next `terraform apply` of an
// existing cluster destroy and re-create every node, the seed too: the
// cluster and its sandboxes are lost. v0.7.0's first cut did exactly that
// with a reworded header comment and a split INSTALL_ARGS line.
//
// New behavior goes behind `%{ if one_line_join }` (or another variable
// whose default renders nothing). If you change the fixture's base values on
// purpose, recompute these from v0.6.13's template, never from today's:
//
//	git show v0.6.13:Terraform/templates/bootstrap.sh.tftpl > /tmp/old.tftpl
//
// then render the fixture against /tmp/old.tftpl (renderBootstrapOutputs)
// and hash each output.
var oldJoinPathRenders = map[string]string{
	"seed":                   "4cc5a94fed2e3d1fed8bbbebefaa123b4899c7e1f721cd9a6288b3da33c9a686",
	"joiner":                 "03513f0e2a6f532785c087a0810135ed7f9bfb303969f5024c6e85fcb396a96e",
	"joiner_kms":             "4f89c95bacfaa495fff0fc77b2eba07de9f5c6ce4a4a1cdeb210710a084cf44a",
	"joiner_audit_s3":        "ecc93de933ed76514335baeeeafd319aeb172e899d35f608182614544a4d3ddd",
	"joiner_audit_file":      "b34d8258a2dd1060645766448c3a0257067f50d255bde7628ecfce3a8b1d23ae",
	"seed_receiver":          "5cadd65d80f95793d202b8d7fe246ff0b2e8c36f2179250cf320f2324a1fbbe8",
	"joiner_receiver":        "39d5a7e06baf39d8f85f8f570a2cc795d482bdcb20cc29aff6f07be33b757f46",
	"seed_public_ca":         "ef16d0f210430df0170c6a3bb5f85ebcb00d94e3bf08a6fbf2bc982a55f05a8e",
	"seed_wrapped":           "c138617e7e6f49767a235af51d4bb5e1146bb522981dfe0d8f01886684db7524",
	"joiner_api_lb":          "ca35dc6ad4bada348167fb3868a8e4b66f84bf2261114f2b44cecbb371551246",
	"joiner_api_lb_worker":   "7190d8fa8b82d598de9ceb28afe61cc3e9efe44df20fb242f4dabe9b164c8296",
	"joiner_routing_on":      "4fc207881b69e2cb87e7ddcd07dcd51af6bad8d6dfe1ea58a624c3020c96d0d4",
	"joiner_routing_off":     "fe78c715ac753507ab7e3e5d767431dc03d6d735713bd42f91d64500c35eda83",
	"joiner_containerd_pool": "9e9fe9bbb857a8f9229de796dc5aa50943bce23cedf7484ad62811d767594809",
	"joiner_download_mirror": "40a245f6e3211f74427fc174a5227334568b604a3e87a2c86bebfc3ebc1f5f89",
}

// An existing cluster (old join path) must render the same user_data as
// v0.6.13, byte for byte, or `terraform apply` replaces every node.
func TestBootstrapOldJoinPathRendersLikeV0613(t *testing.T) {
	outputs := make([]string, 0, len(oldJoinPathRenders))
	for name := range oldJoinPathRenders {
		outputs = append(outputs, name)
	}
	rendered := renderBootstrapOutputs(t, bootstrapTemplatePath(t), outputs...)
	for name, want := range oldJoinPathRenders {
		sum := sha256.Sum256([]byte(rendered[name]))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: the old join path renders differently from v0.6.13 (sha256 %s, want %s); "+
				"every node of an existing cluster would be replaced. Put the change behind %%{ if one_line_join }",
				name, got, want)
		}
	}
}
