# AerolVM access review

- **Window:** 2026-10-16T00:00:00Z to 2026-10-17T12:00:00Z
- **Evidence:** PASS on 3 nodes, 27 records checked; no --witness, so each record was checked to link to the one before it, but no witnessed head was checked
- **Read records:** mixed: plain reads are on record only on node-b; elsewhere a read-only token (viewer, auditor, a metrics scrape) shows no recorded action even when it is used
- **Tokens:** 6 listed by GET /v1/tokens
- **Scope:** this report lists the tokens sandboxd holds and every principal the audit records name in the window. It cannot list people an identity provider would let in who never called the API. Roles are shown for tokens and the operator token; a person who signs in through an identity provider gets a role from the identity file's bindings, which this report does not read.

## Findings

| Flag | Subject | Name | Detail |
|---|---|---|---|
| admin | node:node-b | - | a cluster node calling on its own behalf: admin on every team |
| admin | operator | - | the operator token (PAT): admin on every team |
| admin | tok\_Adm1nQ4xYz00 | platform-admin | role admin on every team |
| admin\_grant | tok\_Adm1nQ4xYz00 | - | minted with role admin on every team by ana@acme.com (oidc:okta:00u1ana) at 2026-10-16T09:05:00Z on node-a |
| expired | tok\_0ldC10000000 | -legacy-ci | expired 2026-10-10T00:00:00Z; it no longer authenticates, and the expiry sweep removes it 30 days after it expired |
| expiring | tok\_Prom5crape00 | prom-scrape | expires 2026-10-30T00:00:00Z, in 12 days |
| revoked | tok\_Gone7Rv0ked0 | - | revoked at 2026-10-16T09:45:00Z by platform-admin (tok\_Adm1nQ4xYz00) on node-a |
| not\_listed | tok\_Gone7Rv0ked0 | old-deploy | acted in the window but is not in the token list: revoked in the window |
| not\_listed | tok\_Swept0ld0000 | old-runner | acted in the window but is not in the token list: revoked, or removed by the expiry sweep |
| no\_recorded\_action | tok\_0ldC10000000 | -legacy-ci | no api record names it in the window; plain reads leave no record unless SB\_AUDIT\_API\_RECORDS=all, so read-only use would not show |
| no\_recorded\_action | tok\_CkOut0000000 | ci-deploy | no api record names it in the window; plain reads leave no record unless SB\_AUDIT\_API\_RECORDS=all, so read-only use would not show |
| no\_recorded\_action | tok\_Prom5crape00 | prom-scrape | no api record names it in the window; plain reads leave no record unless SB\_AUDIT\_API\_RECORDS=all, so read-only use would not show |
| denied | oidc:okta:00u2bob | Bob \| \<b\>\*admin\*\</b\> \[click\](https\://evil.example) www\.evil.example | 1 call refused with 403 |
| denied | oidc:okta:00u9eve | =HYPERLINK("https\://evil.example","report") | 1 call refused with 403 |
| denied | tok\_Aud1tQ4xYz00 | auditor-q4 | 1 call refused with 403 |
| refused | 198.51.100.7 | - | 2 refused credentials (401): expired 2 |
| refused | 203.0.113.9 | - | 5 refused credentials (401): expired 4, malformed 1 |
| rate\_limited | oidc:okta:00u1ana | ana@acme.com | 20 calls summarized by the audit flood budget: their routes are on record, each call is not |
| rate\_limited | tok\_7Hq2abcdEFGH | ci-deploy | 412 calls summarized by the audit flood budget: their routes are on record, each call is not |

## Tokens

| Token | Name | Role | Team | Created by | Created | Expires | Last action | Calls | Flags |
|---|---|---|---|---|---|---|---|---|---|
| tok\_0ldC10000000 | -legacy-ci | runner | checkout | operator | 2026-06-01 | 2026-10-10 | - | - | expired, no\_recorded\_action |
| tok\_Aud1tQ4xYz00 | auditor-q4 | auditor | \* | tok\_Adm1nQ4xYz00 | 2026-10-16 | 2026-12-31 | 2026-10-16T09:31:00Z DELETE /v1/sandboxes/{id} on node-b | api 2 | denied |
| tok\_CkOut0000000 | ci-deploy | runner | checkout | operator | 2026-10-16 | 2027-01-14 | - | - | no\_recorded\_action |
| tok\_7Hq2abcdEFGH | ci-deploy | runner | payments | operator | 2026-09-01 | 2026-11-30 | 2026-10-16T09:30:00Z rate\_limited POST /v1/sandboxes/{id}/toolbox/{path...} on node-a | api 413, secret\_open 1 | rate\_limited |
| tok\_Adm1nQ4xYz00 | platform-admin | admin | \* | oidc:okta:00u1ana | 2026-10-16 | 2027-01-14 | 2026-10-16T09:45:00Z DELETE /v1/tokens/{id} on node-a | api 2 | admin |
| tok\_Prom5crape00 | prom-scrape | viewer | \* | operator | 2026-07-20 | 2026-10-30 | - | - | expiring, no\_recorded\_action |

## Token changes in the window

| When | Change | Token | Role | Team | By | Node | Flags |
|---|---|---|---|---|---|---|---|
| 2026-10-16T09:05:00Z | created | tok\_Adm1nQ4xYz00 | admin | \* | ana@acme.com (oidc:okta:00u1ana) | node-a | admin\_grant |
| 2026-10-16T09:05:00Z | created | tok\_CkOut0000000 | runner | checkout | operator | node-b | - |
| 2026-10-16T09:15:00Z | created | tok\_Aud1tQ4xYz00 | auditor | \* | platform-admin (tok\_Adm1nQ4xYz00) | node-b | - |
| 2026-10-16T09:45:00Z | revoked | tok\_Gone7Rv0ked0 | - | - | platform-admin (tok\_Adm1nQ4xYz00) | node-a | revoked |

## Principals seen in the window

Listed tokens are in the table above and not repeated here.

| Principal | Kind | Name | Teams | Last action | Calls | Flags |
|---|---|---|---|---|---|---|
| node:node-b | node | - | - | 2026-10-16T10:00:00Z DELETE /v1/sandboxes/{id} on node-a | api 1 | admin |
| oidc:okta:00u1ana | oidc | ana@acme.com | \* | 2026-10-16T09:58:00Z rate\_limited POST /v1/sandboxes/{id}/toolbox/{path...} on node-b | api 26 | rate\_limited |
| oidc:okta:00u2bob | oidc | Bob \| \<b\>\*admin\*\</b\> \[click\](https\://evil.example) www\.evil.example | payments | 2026-10-16T09:11:00Z POST /v1/sandboxes/{id}/toolbox/{path...} on node-a | api 1 | denied |
| oidc:okta:00u9eve | oidc | =HYPERLINK("https\://evil.example","report") | checkout | 2026-10-16T09:40:00Z POST /v1/sandboxes on node-b | api 1 | denied |
| operator | operator | - | - | 2026-10-16T09:50:00Z POST /v1/sandboxes on node-b | api 2 | admin |
| sb-3 | sandbox\_key | - | - | 2026-10-16T09:12:00Z ssh on node-b | api 1 | - |
| system:audit | system | - | - | 2026-10-16T09:04:00Z api\_flood\_mode coalesce:coalesce on node-b | api\_flood\_mode 1 | - |
| system:lifecycle | system | - | - | 2026-10-16T09:40:00Z SYSTEM lifecycle.auto\_stop on node-a | api 1 | - |
| tok\_Gone7Rv0ked0 | token | old-deploy | payments | 2026-10-16T09:35:00Z POST /v1/sandboxes/{id}/toolbox/{path...} on node-b | api 1 | not\_listed |
| tok\_Swept0ld0000 | token | old-runner | payments | 2026-10-16T09:55:00Z GET /v1/sandboxes/{id}/toolbox/{path...} on node-b | api 1 | not\_listed |

## Refused credentials

| Source | Refusals | Reasons | Last | Node |
|---|---|---|---|---|
| 203.0.113.9 | 5 | expired 4, malformed 1 | 2026-10-16T09:45:00Z POST /v1/sandboxes | node-b |
| 198.51.100.7 | 2 | expired 2 | 2026-10-16T09:46:00Z POST /v1/sandboxes | node-b |

## Evidence

| Node | Result | Records | From | To | Batches | Read records | Lost | Notes |
|---|---|---|---|---|---|---|---|---|
| node-a | PASS | 13 | 2026-10-15T23:50:00Z | 2026-10-16T10:00:00Z | 3 | mutations | 7 | - |
| node-b | PASS | 14 | 2026-10-16T09:04:00Z | 2026-10-16T09:58:00Z | 3 | all | 0 | 1 re-sent or overlapping batch |
| node-c | PASS | 0 | - | - | 0 | none | 0 | no records in the window |
