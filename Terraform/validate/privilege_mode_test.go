package validate

import (
	"regexp"
	"strings"
	"testing"
)

// Terraform/privilege_mode.tf works out the Firecracker values split needs:
// the kernel in root's folder, and no jailer ids so install.sh's
// sandboxd-jailer user runs the VMs. Those only reach a node if nodes.tf
// hands the bootstrap the locals, not the raw variables, for the seed and for
// every joiner. integration-tests/safety/terraform_privilege_mode_test.go
// tests the locals themselves.
func TestNodesPassTheSplitAwareFirecrackerValues(t *testing.T) {
	nodes := readTF(t, "nodes.tf")
	blocks := map[string]string{
		"seed":   between(t, nodes, `resource "aws_instance" "seed" {`, `resource "aws_instance" "joiner" {`),
		"joiner": between(t, nodes, `resource "aws_instance" "joiner" {`, `resource "aws_s3_object" "joiner_identity" {`),
	}
	for name, block := range blocks {
		for _, k := range []string{"firecracker_kernel_path", "firecracker_jailer_uid", "firecracker_jailer_gid"} {
			want := regexp.MustCompile(`(?m)^\s+` + k + `\s+= local\.` + k + `$`)
			if !want.MatchString(block) {
				t.Errorf("the %s's bootstrap does not take %s = local.%s (Terraform/privilege_mode.tf)", name, k, k)
			}
		}
	}
	for _, raw := range []string{"var.firecracker.kernel_path", "var.firecracker.jailer_uid", "var.firecracker.jailer_gid"} {
		if strings.Contains(nodes, raw) {
			t.Errorf("Terraform/nodes.tf reads %s: split's kernel path and jailer user come from Terraform/privilege_mode.tf", raw)
		}
	}
	// The locals exist where the test of their values loads them from.
	pm := readTF(t, "privilege_mode.tf")
	for _, k := range []string{"firecracker_kernel_path", "firecracker_jailer_uid", "firecracker_jailer_gid", "split_problems"} {
		if !regexp.MustCompile(`(?m)^\s+` + k + `\s+=`).MatchString(pm) {
			t.Errorf("Terraform/privilege_mode.tf does not define local.%s", k)
		}
	}
}
