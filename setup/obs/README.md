# Observability stack (integration-test obs node)

Terraform `deploy_obs=true` provisions a dedicated EC2 instance (not a sandboxd
node) running Prometheus, Grafana, Pushgateway, and grafana-image-renderer via
`docker compose` from this directory.

## The scrape credential at rest

Prometheus authenticates to each sandboxd node's `GET /v1/metrics` with a
bearer token. Terraform renders that token into `prometheus.yml` on the obs host
filesystem, so anyone with SSH or disk access to the obs instance can read it.

- **`cluster.metrics_token` set** (in `config/secrets.yml`): the scrape uses
  it. It must be an `avm_` API token, normally a `viewer` bound to every team:
  `aerolvm token create --name prometheus --role viewer --team '*' --expires-in 90d`.
  That token is **read-only, not metrics-only**: it cannot create, run or
  delete anything, but it can also read every team's sandbox metadata and
  audit records. It needs `SB_IDENTITY_ENABLED=true` on the nodes.
- **`cluster.metrics_token` empty** (the default): the scrape uses the cluster
  PAT, exactly as before. Integration-test clusters use throwaway PATs
  destroyed with the stack; do not reuse this for long-lived production
  secrets.
- **`SB_PAT_SCOPE=host`** refuses the PAT from the obs host, so set
  `metrics_token` before turning it on. The bootstrap is two steps: bring the
  cluster up, mint the token on a node with the PAT
  (`SB_API_URL=http://127.0.0.1:21212`), set `cluster.metrics_token`, and
  re-apply.

Rotation, the first admin token and turning on host scope are in
[`setup/runbooks/identity-and-access.md`](../runbooks/identity-and-access.md).

## Pushgateway

Pushgateway listens on the obs host's private interface (VPC-scoped security
group). Suite simulations (Lane B) push per-runtime benchmark rows here; Grafana
dashboard D2 reads `job="pushgateway"` series.

## Operator access

Grafana is exposed on `:3000` from `admin_allowed_cidrs` only. The admin
password is generated per deploy (`terraform output -raw grafana_admin_password`).
