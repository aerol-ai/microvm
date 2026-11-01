package safety

import (
	"regexp"
	"strings"
	"testing"
)

// The load balancer in front of the ingress nodes (Terraform
// api_load_balancer, load_balancer.tf) has three properties a refactor could
// drop without any plan failing, because nothing in CI runs `terraform test`
// (the mocked-provider runs are described in the PR that added it):
//
//   - the client's address reaches Caddy (client IP preservation). Without it
//     every caller looks like the balancer: the audit log, the 401 limiter and
//     SB_PAT_SCOPE all key on that address.
//   - the plain-HTTP health listener is open to the balancer's security group
//     and nothing else, and admin_allowed_cidrs stays the only admin source.
//   - with the balancer off (the default) DNS is exactly what it was.
func TestAPILoadBalancerKeepsItsGuarantees(t *testing.T) {
	vars := readRepoFile(t, "Terraform", "variables.tf")
	if v := hclBlock(vars, `variable "api_load_balancer"`); !regexp.MustCompile(`default\s*=\s*"none"`).MatchString(v) {
		t.Fatalf(`api_load_balancer must default to "none", so an existing deployment plans no change:\n%s`, v)
	}

	lb := readRepoFile(t, "Terraform", "load_balancer.tf")
	tg := hclBlock(lb, `resource "aws_lb_target_group" "api"`)
	if !strings.Contains(tg, `preserve_client_ip = "true"`) || !strings.Contains(tg, `target_type = "instance"`) {
		t.Errorf("target groups must be instance targets that preserve the client address:\n%s", tg)
	}
	hc := hclBlock(tg, "health_check")
	for _, want := range []string{`protocol            = "HTTP"`, `path                = "/health"`, "var.api_lb_health_check_port", "unhealthy_threshold = 2", "interval            = 5"} {
		if !strings.Contains(hc, want) {
			t.Errorf("health check lacks %q (it must probe the Caddy /health listener and drop a node within ~10 s):\n%s", want, hc)
		}
	}
	if !strings.Contains(hclBlock(lb, `resource "aws_lb" "api"`), `load_balancer_type = "network"`) {
		t.Error("the balancer must be an NLB: TCP passthrough keeps TLS on Caddy and SNI routing on caddy-l4")
	}

	health := hclBlock(lb, `resource "aws_security_group_rule" "node_lb_health"`)
	if !strings.Contains(health, "source_security_group_id = aws_security_group.api_lb[0].id") || strings.Contains(health, "cidr_blocks") {
		t.Errorf("the health listener must be open to the balancer's security group only:\n%s", health)
	}
	if strings.Contains(lb, "var.admin_allowed_cidrs") {
		t.Error("load_balancer.tf must not touch admin_allowed_cidrs")
	}

	dns := readRepoFile(t, "Terraform", "dns.tf")
	if !strings.Contains(dns, "ingress_dns_targets = local.api_lb_enabled ? { lb = aws_eip.api_lb[0].public_ip } : local.ingress_ip_by_node") {
		t.Error("with the balancer off, apex and wildcard must keep pointing at ingress_ip_by_node, keyed by node")
	}
	for _, rec := range []string{`resource "cloudflare_record" "apex"`, `resource "cloudflare_record" "wildcard"`} {
		if !strings.Contains(hclBlock(dns, rec), "local.ingress_dns_targets") {
			t.Errorf("%s must use ingress_dns_targets", rec)
		}
	}
	if direct := hclBlock(dns, `resource "cloudflare_record" "l4_direct"`); !strings.Contains(direct, "proxied = false") {
		t.Errorf("tcp.<domain> must never be proxied: Cloudflare's proxy does not carry raw TCP:\n%s", direct)
	}
}

// run.sh turns the api-load-balancer capability into Terraform's
// api_load_balancer on the apply AND the destroy, as it does deploy_obs for
// observability. The capability is the one switch: a scenario that gates
// UC-356 gets the balancer, and an operator's terraform.tfvars cannot put one
// under the other scenarios.
func TestHarnessDerivesTheLoadBalancerFromTheCapability(t *testing.T) {
	run := readRepoFile(t, "integration-tests", "run.sh")
	fn := hclBlock(run, "api_lb_tfvar() {")
	if !strings.Contains(fn, `contains(["api-load-balancer"])`) || !strings.Contains(fn, `echo "nlb"`) || !strings.Contains(fn, `echo "none"`) {
		t.Fatalf("api_lb_tfvar must map the api-load-balancer capability to nlb, else none:\n%s", fn)
	}
	if n := strings.Count(run, `-var="api_load_balancer=$(api_lb_tfvar `); n != 2 {
		t.Fatalf("api_load_balancer is passed %d times; want the apply and the destroy", n)
	}
	if !strings.Contains(hclBlock(run, "destroy_scenario() {"), "api_load_balancer=") {
		t.Fatal("destroy_scenario does not pass api_load_balancer")
	}
	caps := readRepoFile(t, "integration-tests", "scenarios", "cluster-3-mixed-lb.caps.yml")
	for _, want := range []string{"- api-load-balancer", "- domain", "- cluster", "disruptive: true"} {
		if !strings.Contains(caps, want) {
			t.Errorf("cluster-3-mixed-lb.caps.yml lacks %q; UC-356 would skip there", want)
		}
	}
}
