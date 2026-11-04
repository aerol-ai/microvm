# Private-cloud egress scenario (plans/egress-domain-filtering.md §5.10,
# P1-20). Same single mixed node as single-node.tfvars; extra_user_data builds
# the bank-network stand-ins the private-cloud UCs (UC-186..189) talk to and
# points the egress operator file at them:
#
#   - dnsmasq on 127.0.0.1:5353 answers svc.corp.itest.internal and
#     rebind.itest.example with the internal service's two addresses (below)
#     and forwards the rest to the VPC resolver. The egress gateway uses it as
#     its upstream resolver (SB_EGRESS_DNS_UPSTREAMS).
#   - python's http.server on :8081, in a network namespace at .250.2 and
#     .250.3 of the node's /16, is the internal service: another host in
#     the zone, since the node itself is closed to filtered sandboxes.
#   - squid on :3128 is the upstream proxy.
#   - /etc/sandboxd/egress-policy.yaml: internal_zone corp.itest.internal
#     → this node's /16, deny_cidrs [1.0.0.1/32], the control-port guard, and
#     upstream_proxy → squid. default_policy stays open (see the caps file).
#     rebind.itest.example is no_proxy: UC-187's rebinding probe needs it
#     resolved directly (dnsmasq points it into the zone), and a name the
#     proxy carries can't take a port other than 80 or 443 at all.
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
    role            = "mixed"
    seed            = true
    spot            = true
    extra_user_data = <<-EOT
      set -eux
      NODE_IP=$(hostname -I | awk '{print $1}')
      ZONE_CIDR="$(echo "$NODE_IP" | cut -d. -f1-2).0.0/16"
      VPC_DNS=$(awk '/^nameserver/ {print $2; exit}' /run/systemd/resolve/resolv.conf 2>/dev/null || true)
      VPC_DNS=$${VPC_DNS:-169.254.169.253}
      sudo apt-get update -qq
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq squid dnsmasq-base
      # The internal service is another host inside the zone, as in a bank
      # network, not the node: the node itself is closed to filtered
      # sandboxes. A network namespace behind a veth stands in for it, with
      # two addresses so the rebinding probe can't ride the pair the
      # legitimate name opened.
      INT_NET="$(echo "$NODE_IP" | cut -d. -f1-2).250"
      sudo ip netns add itest-internal
      sudo ip link add itest-int0 type veth peer name itest-int1
      sudo ip link set itest-int1 netns itest-internal
      sudo ip addr add "$INT_NET.1/29" dev itest-int0
      sudo ip link set itest-int0 up
      sudo ip netns exec itest-internal ip addr add "$INT_NET.2/29" dev itest-int1
      sudo ip netns exec itest-internal ip addr add "$INT_NET.3/29" dev itest-int1
      sudo ip netns exec itest-internal ip link set itest-int1 up
      sudo ip netns exec itest-internal ip link set lo up
      sudo ip netns exec itest-internal ip route add default via "$INT_NET.1"
      sudo systemd-run --unit itest-dnsmasq dnsmasq --keep-in-foreground --no-resolv \
        --listen-address=127.0.0.1 --port=5353 --bind-interfaces --server="$VPC_DNS" \
        --address=/svc.corp.itest.internal/"$INT_NET.2" --address=/rebind.itest.example/"$INT_NET.3"
      sudo mkdir -p /srv/itest-internal
      echo internal-ok | sudo tee /srv/itest-internal/index.html >/dev/null
      sudo systemd-run --unit itest-internal-http ip netns exec itest-internal python3 -m http.server 8081 --bind 0.0.0.0 --directory /srv/itest-internal
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
        no_proxy: [rebind.itest.example]
      POLICY
      sudo chmod 0644 /etc/sandboxd/egress-policy.yaml
      echo 'SB_EGRESS_OPERATOR_FILE=/etc/sandboxd/egress-policy.yaml' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      printf 'SB_EGRESS_OPERATOR_FILE=/etc/sandboxd/egress-policy.yaml\nSB_EGRESS_DNS_UPSTREAMS=127.0.0.1:5353\n' | sudo tee -a /etc/sandboxd/egress-gateway.env >/dev/null
      sudo systemctl restart aerolvm-egress-gateway.service
      sudo systemctl restart sandboxd
    EOT
  }
}
