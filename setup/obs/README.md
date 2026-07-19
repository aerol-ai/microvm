# Observability stack (integration-test obs node)

Terraform `deploy_obs=true` provisions a dedicated EC2 instance (not a sandboxd
node) running Prometheus, Grafana, Pushgateway, and grafana-image-renderer via
`docker compose` from this directory.

## PAT at rest

Prometheus authenticates to each sandboxd node's `GET /v1/metrics` with the
cluster PAT. Terraform renders that token into `prometheus.yml` on the obs host
filesystem. Anyone with SSH or disk access to the obs instance can read it.
Integration-test clusters use throwaway PATs destroyed with the stack; do not
reuse this pattern for long-lived production secrets without additional
hardening (short-lived scrape tokens, Secrets Manager, etc.).

## Pushgateway

Pushgateway listens on the obs host's private interface (VPC-scoped security
group). Suite simulations (Lane B) push per-runtime benchmark rows here; Grafana
dashboard D2 reads `job="pushgateway"` series.

## Operator access

Grafana is exposed on `:3000` from `admin_allowed_cidrs` only. The admin
password is generated per deploy (`terraform output -raw grafana_admin_password`).
