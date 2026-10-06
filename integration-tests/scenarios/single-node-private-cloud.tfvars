# Private-cloud egress scenario (plans/egress-domain-filtering.md §5.10,
# P1-20). Same single mixed node as single-node.tfvars; extra_user_data builds
# the bank-network stand-ins the private-cloud UCs (UC-186..189) talk to and
# points the egress operator file at them:
#
#   - dnsmasq on 127.0.0.1:5353 answers svc.corp.itest.internal and
#     rebind.itest.example with this node's private address and forwards the
#     rest to the VPC resolver. The egress gateway uses it as its upstream
#     resolver (SB_EGRESS_DNS_UPSTREAMS).
#   - python's http.server on :8081 is the internal service.
#   - squid on :3128 is the upstream proxy.
#   - /etc/sandboxd/egress-policy.yaml: internal_zone corp.itest.internal
#     → this node's /16, deny_cidrs [1.0.0.1/32], the control-port guard, and
#     upstream_proxy → squid. default_policy stays open (see the caps file).
#
# AWS access is inherited from config/terraform.tfvars (run.sh chains it first).
cluster_name = "aerolvm-itest-single-node-private-cloud"

extra_tags = {
  itest = "true"
  ttl   = "4" # hours; reaper terminates older instances
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = false
}

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
    extra_user_data = <<-EOT
      set -eux
      NODE_IP=$(hostname -I | awk '{print $1}')
      ZONE_CIDR="$(echo "$NODE_IP" | cut -d. -f1-2).0.0/16"
      VPC_DNS=$(awk '/^nameserver/ {print $2; exit}' /run/systemd/resolve/resolv.conf 2>/dev/null || true)
      VPC_DNS=$${VPC_DNS:-169.254.169.253}
      sudo apt-get update -qq
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq squid dnsmasq-base
      sudo systemd-run --unit itest-dnsmasq dnsmasq --keep-in-foreground --no-resolv \
        --listen-address=127.0.0.1 --port=5353 --bind-interfaces --server="$VPC_DNS" \
        --address=/svc.corp.itest.internal/"$NODE_IP" --address=/rebind.itest.example/"$NODE_IP"
      sudo mkdir -p /srv/itest-internal
      echo internal-ok | sudo tee /srv/itest-internal/index.html >/dev/null
      sudo systemd-run --unit itest-internal-http python3 -m http.server 8081 --bind 0.0.0.0 --directory /srv/itest-internal
      printf 'acl itest_src src 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16\nhttp_access allow itest_src\n' | sudo tee /etc/squid/conf.d/itest.conf >/dev/null
      sudo systemctl restart squid
      sudo tee /etc/sandboxd/egress-policy.yaml >/dev/null <<POLICY
      version: 1
      internal_zone:
        suffixes: [corp.itest.internal]
        cidrs: [$ZONE_CIDR]
      deny_cidrs: [1.0.0.1/32]
      node_control_port_guard: true
      upstream_proxy:
        url: http://$NODE_IP:3128
      POLICY
      sudo chmod 0644 /etc/sandboxd/egress-policy.yaml
      echo 'SB_EGRESS_OPERATOR_FILE=/etc/sandboxd/egress-policy.yaml' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      printf 'SB_EGRESS_OPERATOR_FILE=/etc/sandboxd/egress-policy.yaml\nSB_EGRESS_DNS_UPSTREAMS=127.0.0.1:5353\n' | sudo tee -a /etc/sandboxd/egress-gateway.env >/dev/null
      sudo systemctl restart aerolvm-egress-gateway.service
      sudo systemctl restart sandboxd
    EOT
  }
}
