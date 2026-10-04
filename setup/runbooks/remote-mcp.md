# Runbook: Remote MCP

Use this when agents connected to sandboxd's remote MCP endpoint (`/mcp`)
report failures, or when `SandboxdRemoteMCPErrorRate` fires.

The endpoint is off unless `SB_MCP_ENABLED=true`. It is stateless: each
request names one sandbox in `?sandbox=`, authenticates with the API token in
the `Authorization` header, and its tools call the v1 API in-process with
that same token. So almost every failure is an ordinary API failure seen
through MCP. Design: `plans/mcp-server-and-agent-cli.md` §5.7.

## Alerts

- `SandboxdRemoteMCPErrorRate`: over 20% of tool calls ended in
  `api_error` for 10 minutes.

## Severity

| Severity | Criteria |
|---|---|
| SEV-2 | Most remote tool calls fail across tenants (platform failure). |
| SEV-3 | One tool, one tenant or one sandbox fails; others work. |

## First Checks

1. Open the "Remote MCP" row of the sandboxd SLOs dashboard. The outcome
   panel separates `ok`, `tool_error` (the model can fix it: not found,
   bad argument, edit conflict), `api_error` (the platform failed) and
   `unauthorized`.
2. Find the failing calls in the logs. Each tool call writes one line with
   the tool, sandbox, owner, outcome, error code and duration, never the
   arguments or output:

   ```bash
   sudo journalctl -u sandboxd --since "30 minutes ago" --no-pager \
     | grep '"mcp tool call"' | grep '"outcome":"api_error"'
   ```

3. Group by `code`:

| Code | Likely cause | Next step |
|---|---|---|
| `unavailable` | owner node unreachable, failover in progress, 503 from capacity | check cluster health; the same calls fail on `/v1` |
| `unreachable` | the API handler could not reach a peer | check cluster mTLS and membership |
| `timeout` | slow toolbox or a long `exec` | check `duration_ms`; `exec` defaults to 300 s |
| `internal` | toolbox or API 5xx | read the sandboxd error lines around the call |

4. Reproduce outside MCP with the same token. Remote tool calls are API
   calls, so the CLI shows the same failure with more detail:

   ```bash
   aerolvm get <sandbox> --debug
   aerolvm exec <sandbox> -- true
   ```

## Request-Level Refusals

`aerolvm_mcp_requests_total` counts requests refused before any tool ran:

| Key | Meaning |
|---|---|
| `bad_request` | a query parameter is invalid; the 400 body names it |
| `unauthorized` | missing or wrong token |
| `rate_limited` | the token passed `SB_MCP_RATE_LIMIT` (per token, burst 2x) |
| `forbidden_origin` | a browser page sent an `Origin` not in `SB_MCP_ALLOWED_ORIGINS` |
| `forbidden_host` | the `Host` is not in `SB_MCP_ALLOWED_HOSTS` |

A burst of `forbidden_origin` from one source is a DNS-rebinding or
cross-site attempt; the endpoint refuses it before authentication, so
nothing leaked.

## Turning It Off

Set `SB_MCP_ENABLED=false` and restart sandboxd. `/mcp` then answers 404.
Nothing else depends on it, and sandboxes created through it keep their idle
lifecycle (stop after 30 minutes, destroy after 24 hours).
