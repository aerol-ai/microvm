package safety

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// hclBlock returns the brace-balanced block that opens with header, or "".
func hclBlock(src, header string) string {
	i := strings.Index(src, header)
	if i < 0 {
		return ""
	}
	depth := 0
	for j := i; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[i : j+1]
			}
		}
	}
	return ""
}

func readRepoFile(t *testing.T, rel ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, rel...)...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// The module once defaulted admin_allowed_cidrs to 0.0.0.0/0, so a
// deployment that never set it served SSH and the daemon API to the whole
// internet (UC-328, bank-readiness campaign). The variable is now required
// and a world-open value needs an explicit opt-in; these checks keep either
// half from quietly coming back.
func TestAdminCIDRsAreNeverWorldOpenByDefault(t *testing.T) {
	vars := readRepoFile(t, "Terraform", "variables.tf")
	v := hclBlock(vars, `variable "admin_allowed_cidrs"`)
	if v == "" {
		t.Fatal(`variables.tf has no admin_allowed_cidrs variable`)
	}
	if regexp.MustCompile(`(?m)^\s*default\s*=`).MatchString(v) {
		t.Fatalf("admin_allowed_cidrs has a default again; an operator who never sets it gets that value on SSH and the API:\n%s", v)
	}
	if !strings.Contains(v, "validation") {
		t.Fatal("admin_allowed_cidrs lost its validation: an empty list or a malformed CIDR reaches the security group")
	}
	opt := hclBlock(vars, `variable "allow_admin_from_anywhere"`)
	if !regexp.MustCompile(`default\s*=\s*false`).MatchString(opt) {
		t.Fatalf("allow_admin_from_anywhere must exist and default to false:\n%s", opt)
	}

	// The gate sits on admin_ssh because that rule is created on every
	// deployment, so a world-open value stops every apply, obs node or not.
	net := readRepoFile(t, "Terraform", "network.tf")
	ssh := hclBlock(net, `resource "aws_security_group_rule" "admin_ssh"`)
	if ssh == "" {
		t.Fatal("network.tf has no admin_ssh rule")
	}
	pre := hclBlock(ssh, "precondition")
	for _, want := range []string{"var.allow_admin_from_anywhere", "var.admin_allowed_cidrs", `split("/", c)[1]) > 0`} {
		if !strings.Contains(pre, want) {
			t.Errorf("admin_ssh precondition does not mention %s:\n%s", want, pre)
		}
	}

	// Monitoring and peers reach :21212 over private addresses; with the
	// world-open default gone they need their own VPC-scoped rule.
	api := hclBlock(net, `resource "aws_security_group_rule" "vpc_api"`)
	if !strings.Contains(api, "21212") || !strings.Contains(api, "[var.vpc_cidr]") {
		t.Errorf("no VPC-scoped :21212 rule; the obs node and peers lose the API:\n%s", api)
	}

	// Every rule fed by admin_allowed_cidrs exists only alongside admin_ssh's
	// gate, never with a literal world-open range of its own.
	for _, f := range []string{"network.tf", "obs.tf"} {
		src := readRepoFile(t, "Terraform", f)
		for _, m := range regexp.MustCompile(`resource "aws_security_group_rule" "(\w+)"`).FindAllStringSubmatch(src, -1) {
			b := hclBlock(src, m[0])
			if strings.Contains(b, "var.admin_allowed_cidrs") && strings.Contains(b, `"0.0.0.0/0"`) && m[1] != "admin_ssh" {
				t.Errorf("%s: rule %s widens the admin CIDRs with 0.0.0.0/0", f, m[1])
			}
		}
	}
}

// run.sh must learn the admin CIDR after the safety gate (nothing leaves the
// machine before it) and before the apply, and chain it into the var-files
// the apply and the destroy share; otherwise every scenario fails at plan
// time on the required variable.
func TestHarnessSuppliesAdminCIDRs(t *testing.T) {
	run := readRepoFile(t, "integration-tests", "run.sh")
	args := hclBlock(run, "tf_varfile_args() {")
	if !strings.Contains(args, "admin-cidrs.tfvars") {
		t.Fatal("tf_varfile_args does not chain admin-cidrs.tfvars")
	}
	gate := strings.Index(run, `bash "$PROVISION" check-safety`)
	emit := strings.Index(run, `emit_admin_cidrs_tfvars "$sdir"`)
	apply := strings.Index(run, `terraform -chdir="${REPO_ROOT}/Terraform" apply`)
	if gate < 0 || emit < 0 || apply < 0 || emit < gate || emit > apply {
		t.Fatalf("emit_admin_cidrs_tfvars must run after the safety gate and before the apply (gate %d, emit %d, apply %d)", gate, emit, apply)
	}
	destroy := hclBlock(run, "destroy_scenario() {")
	if !strings.Contains(destroy, "admin_allowed_cidrs=") {
		t.Fatal("destroy_scenario has no admin_allowed_cidrs fallback; a stack applied before admin-cidrs.tfvars existed cannot be destroyed")
	}
}
