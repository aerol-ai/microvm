# Customer key custody: HashiCorp Vault and PKCS#11 (HSM) key providers

Status: **DRAFT 2026-10-20**, not reviewed. Next step: `/plan-eng-review`, then
founder decisions F1–F3 (under "Decisions needed"). Nothing here is built.

Source of the ask: the enterprise gap list row

| Requirement | Today | Gap |
|---|---|---|
| Keys in their own key store (HSM or Vault) | AWS KMS only | Add Vault or PKCS#11 support |

## In one paragraph

Customers want the keys that protect their data to live in **their** key store:
HashiCorp Vault (or its fork OpenBao), or a hardware security module (HSM)
reached through PKCS#11, the standard C interface every HSM vendor ships. Today
AerolVM can hand key custody only to AWS KMS, and even then only for one class
of data. This plan adds two key providers, `vault` and `pkcs11`, on the
existing `DataKeyWrapper` seam. It also closes a gap the "AWS KMS only" row
hides: the **server key**, a plain 32-byte file on every node, still encrypts
most stored secrets no matter which provider is set. The plan wraps that key
with the customer's key store too, so no long-lived decryption key is left on
disk.

## What the code does today

Each fact was checked against `main` at `987f6779` on 2026-10-20.

1. **The seam exists and is small.** `DataKeyWrapper` has two methods, `Wrap`
   and `Unwrap` (`pkg/secrets/kms.go:16-19`). `KMSProvider` works with any
   wrapper (`pkg/secrets/kms_provider.go`). AWS KMS is the only real one
   (`pkg/secrets/awskms.go`). `FakeKMS` is the offline test double
   (`pkg/secrets/fake_kms.go`).
2. **`vault` is a reserved name that refuses to boot.** See
   `pkg/secrets/factory.go:62` and `internal/config/config.go:2599`. The docs
   say "Planned" (`docs/src/content/docs/cluster-secrets.mdx:33`, `:121`).
   There is no `pkcs11` name.
3. **The provider covers only cluster-secret copies.** These are the sealed
   copies a cluster sends to backup nodes. Everything else is sealed with the
   **server key** (`SB_CREDENTIAL_ENCRYPTION_KEY`, or the file at
   `SB_CREDENTIAL_ENCRYPTION_KEY_PATH`). That covers:
   - registry auth: `internal/service/service.go:2724`;
   - sandbox env: `internal/service/service.go:2824`;
   - mount credentials: `internal/service/service.go:2953`;
   - the egress-inspection CA private key: `internal/service/egress_inspect.go:142`;
   - plaintext env left by old releases, sealed at store open:
     `internal/store/env_binding_migration.go:82`;
   - cluster-secret copies under the `local` provider.

   The docs already say this: "Secrets in each server's own database still use
   that server's key" (`docs/src/content/docs/enterprise/architecture.mdx:178`).
4. **The server key is plaintext at rest.** `loadOrGenerateKey` reads base64
   from env or a file, or writes a new one at mode 0600
   (`pkg/secrets/secrets.go:92-130`). Anyone who copies the disk, or a backup
   of `/var/lib/sandboxd`, can decrypt every sealed row offline, forever.
5. **The server key is loaded before anything else.** `NewCipher` runs before
   the store opens, because the store migration needs it
   (`pkg/daemon/daemon.go:152-158`). The provider is set up much later
   (`pkg/daemon/daemon.go:314`). So a key-store client that unwraps the server
   key must exist before `NewCipher`.
6. **A wrapped DEK does not say who wrapped it.** The envelope stores
   `WrappedKey` bytes with no provider tag (`pkg/secrets/envelope.go`). If you
   switch `SB_SECRET_PROVIDER` on a live cluster, existing rows fail with a
   decrypt error and no explanation.
7. **Throttling is counted, not handled.** `ErrProviderThrottled` reaches only
   a metric (`internal/service/metrics.go:316`). Nothing retries or limits
   concurrency. AWS KMS quotas are high enough that this has not mattered. An
   HSM partition with a small session limit will hit it.
8. **The key store is on the create path in cluster mode.** A cluster create
   with secrets calls `Put` once, which calls `Wrap` once
   (`internal/service/seal_distribute.go:478`, reached from
   `pkg/api/clustercreate/clustercreate.go:541` and `overlap.go:201`). Opens
   happen on restart, failover and recreate (`internal/service/cluster_secrets.go:125`,
   `:1708`).
9. **sandboxd is already a cgo binary.** The release builds it with
   `CGO_ENABLED=1` (`.github/workflows/release.yml:229`) for `go-sqlite3`. So a
   PKCS#11 library that loads the vendor's `.so` at runtime adds no new build
   requirement.

## Scope rule carried over

`plans/secrets-hardening.md:915-927` (E5) still holds. **The platform key store
holds only AerolVM's own wrapping keys.** It is not a store for customer
application secrets. This plan does not add "read my secrets from Vault at
create time". Customers still pass secrets at create time from their own
systems.

## The claim this plan lets us make

Write the docs from this section, and do not go beyond it.

**With `SB_SECRET_PROVIDER` set to `awskms`, `vault` or `pkcs11`, and the
server key wrapped:**

- No long-lived key that decrypts AerolVM-held secrets is stored in plaintext
  outside your key store.
- A stolen disk, a database backup or a copied state directory decrypts
  nothing on its own. The thief must also be able to call your key store.
- Every unwrap is a call your key store can log and deny. If you disable the
  key, no node can decrypt anything after its next restart. Rows sealed with
  that key become unreadable for good. This is crypto-shredding, and it is a
  feature: it is how you revoke AerolVM's access.

**It does not cover:**

- **A running node.** sandboxd holds the unwrapped server key and the DEKs it
  is using in memory. Root on a running node can read them. This is true of
  every envelope scheme, AWS KMS included.
- **The credential that reaches the key store.** The node still holds a Vault
  token (or reaches a local Vault Agent), or an HSM PIN file. Stealing it lets
  an attacker decrypt only while they can reach your key store, and every call
  shows in its log. That is the whole improvement over a key file, so say it
  that way.
- **Secrets inside sandboxes.** Once a secret is injected, the guest has it.
- **Other node credentials.** These are covered under Non-goals.

## Goals

- `SB_SECRET_PROVIDER=vault` works with HashiCorp Vault and OpenBao through
  the Transit engine.
- `SB_SECRET_PROVIDER=pkcs11` works with any HSM that supports AES-GCM through
  PKCS#11. Test with SoftHSM2 and AWS CloudHSM, and name only tested vendors in
  the docs.
- The server key can be stored only in wrapped form, under the same provider,
  including `awskms`.
- No change unless it is configured. The `local` provider stays the default
  and never contacts anything. Single-node and local mode are unchanged.
- No new work on `CreateSandbox` beyond what `awskms` already does.

## Non-goals (v1)

- **Customer secret storage or brokering.** E5 stays out of scope.
- **Node TLS keys, the cluster CA key, or audit-head signing in an HSM.** The
  CA key already belongs offline (`setup/cluster.md:1185-1220`). HSM signing
  of audit heads is its own follow-up (`plans/secrets-hardening.md:1014`).
  The PKCS#11 session code here can be reused for both later.
- **Shared tokens and credentials.** This covers the gossip key, PAT,
  audit-ingest token, webhook HMAC key and the upstream (AOCR) wrap key. They
  are credentials, not data-encryption keys. Operators can already source them
  from Vault with Vault Agent templates.
- **Rotating the server key itself.** The `Cipher` format has no key ID, so
  rotating the data key means resealing every row. Rotating the **key-store
  key that wraps it** is in scope and cheap (see "Rotation").
- **Live provider switching.** Changing providers on a running cluster stays
  unsupported in v1. Rows get tagged now so a later tool needs no format
  change.
- **KMIP, GCP Cloud KMS and Azure Key Vault.** Each would be one new wrapper on
  the same seam. Build one only when a customer asks.
- **A DEK cache.** `plans/secrets-hardening.md:907` keeps its rule: no cache
  without measured throttling.

## Design

### Shape: one key-store client, two uses

```
                    customer key store (AWS KMS | Vault Transit | HSM)
                          ▲ Wrap / Unwrap (DataKeyWrapper)
          ┌───────────────┴────────────────┐
   (A) per-row DEKs                 (B) the server key
   cluster-secret copies            wrapped once, unwrapped at boot
   kms_provider.go (unchanged)      → *secrets.Cipher (format unchanged)
                                      seals env, registry, mounts,
                                      egress CA key, local cluster secrets
```

(A) already works through `KMSProvider`. (B) is new. Neither changes any
on-disk ciphertext format. (B) changes only how the 32 bytes reach memory, so
no env, mount or registry rows need migrating.

### 1. The `vault` provider (Vault Transit, OpenBao)

**Key setup (customer side, in the docs).** Create a Transit key of type
`aes256-gcm96` with `exportable=false`, `allow_plaintext_backup=false` and
`deletion_allowed=false`. The node's policy grants `update` on
`<mount>/encrypt/<key>` and `<mount>/decrypt/<key>` and nothing else.

**Calls.** `Wrap` → `POST /v1/<mount>/encrypt/<key>` with
`plaintext=b64(dek)` and `associated_data=b64(encryptionContextAAD(encCtx))`.
`encryptionContextAAD` already exists in `fake_kms.go`; move it next to the
interface. `Unwrap` → `POST /v1/<mount>/decrypt/<key>`. Vault and OpenBao both
document `associated_data` for AEAD key types on encrypt. Phase 0 must confirm
that decrypt **rejects** the wrong AAD on both. If it does not, bind the
context through a derived key (`derived=true` plus `context`) instead.

**Client.** A thin HTTP client in `pkg/secrets/vault.go`, in the style of
`pkg/caddy/client.go`. Do not use `github.com/hashicorp/vault/api`: we need two
endpoints, and that module brings a large dependency tree into a security
package. The `vaultAPI` interface is narrowed for tests, the way `kmsAPI` is
(`awskms.go:16-19`).

**Auth (v1): no login code in sandboxd.** Two modes, both built on Vault
Agent, which supports AppRole, Kubernetes, AWS IAM, TLS certificates and the
other methods:

- `SB_SECRET_VAULT_TOKEN_FILE`: Agent's auto-auth writes a token to this
  file. sandboxd reads it when it changes, and once more after a 403 before
  reporting "denied".
- No token file, with `SB_SECRET_VAULT_ADDR=http://127.0.0.1:<port>`: Agent's
  API proxy adds the token itself (`use_auto_auth_token`). sandboxd holds no
  Vault credential at all.

Refuse any `http://` address that is not loopback. Direct login methods wait
for a customer who cannot run Vault Agent.

**Settings.**

| Variable | Meaning |
|---|---|
| `SB_SECRET_VAULT_ADDR` | Vault or OpenBao URL (or the local Agent proxy) |
| `SB_SECRET_VAULT_TRANSIT_MOUNT` | Default `transit` |
| `SB_SECRET_VAULT_KEY_NAME` | Transit key name; required |
| `SB_SECRET_VAULT_TOKEN_FILE` | Optional; see Auth |
| `SB_SECRET_VAULT_NAMESPACE` | Vault Enterprise namespace (`X-Vault-Namespace`) |
| `SB_SECRET_VAULT_CACERT` | CA bundle for a private PKI |

**Errors** go into the existing classes so metrics and runbooks keep working:

| Vault response | Error |
|---|---|
| 400 with an authentication or decrypt failure | `ErrDecryptFailed` |
| 403, still 403 after one token reload | `ErrProviderDenied` |
| 429 | `ErrProviderThrottled` |
| 5xx, sealed, connection refused or timeout | `ErrProviderUnavailable` |

**Rotation.** Transit versions its keys itself. Ciphertext carries
`vault:vN:`, new wraps use the latest version, and old rows still decrypt
until the operator raises `min_decryption_version`. Before raising it, a
rewrap sweep must move live rows to the new version. Transit's `rewrap`
endpoint does this without exposing the DEK to sandboxd. That sweep is
follow-up F-R1. Until it lands, the docs tell operators not to raise
`min_decryption_version`.

### 2. The `pkcs11` provider (HSMs)

**Library.** Use `github.com/miekg/pkcs11`. It loads the vendor module with
`dlopen` at runtime, so nothing vendor-specific is linked at build time. We
need one mechanism and a session pool, about 300 lines. The `crypto11` family
(ThalesGroup, now forked as `eclipse-keypont/crypto11`) is the reference for
vendor quirks, especially the CloudHSM GCM IV. Phase 0 makes the final choice.

**Key and mechanism.** One AES-256 key object with `CKA_TOKEN`,
`CKA_SENSITIVE`, `CKA_ENCRYPT` and `CKA_DECRYPT` set to true, and
`CKA_EXTRACTABLE` set to false. `Wrap` is `C_Encrypt` of the 32-byte DEK with
`CKM_AES_GCM`, using AAD = `encryptionContextAAD(encCtx)` and a 128-bit tag.
`Unwrap` is `C_Decrypt`.

- **The IV.** AWS CloudHSM refuses an IV from the caller and writes its own
  into `CK_GCM_PARAMS.pIv`. SoftHSM2 accepts the caller's IV. Support both with
  `SB_SECRET_PKCS11_GCM_IV=hsm|caller` (default `hsm`). Phase 0 checks whether
  probing the HSM can detect this instead.
- **No-GCM fallback.** `CKM_AES_KEY_WRAP_PAD` (RFC 5649) has no AAD. It would
  still be safe, because the v4 envelope already binds the sandbox identity
  into the payload AAD (`envelope.go:21-24`). A wrapped key moved to another
  row therefore still fails at payload open. Ship it **only** if Phase 0 finds
  a target HSM without GCM.

**Wrapped format** (ours, versioned): `p11:1:` + key-label length + key label +
IV + ciphertext and tag. The label is what makes rotation work.

**Sessions.** Call `C_Initialize` once with `CKF_OS_LOCKING_OK`, because Go
calls in from many OS threads. Log in once as the user; on a token, one login
covers all sessions. Keep a bounded pool of `SB_SECRET_PKCS11_MAX_SESSIONS`
sessions (default 8). These return codes reopen the session and retry once:
`CKR_SESSION_HANDLE_INVALID`, `CKR_SESSION_CLOSED`, `CKR_DEVICE_REMOVED` and
`CKR_TOKEN_NOT_PRESENT`. After that, errors map to the existing classes:

| PKCS#11 result | Error |
|---|---|
| `CKR_SESSION_COUNT`, `CKR_DEVICE_MEMORY`, pool wait timeout | `ErrProviderThrottled` |
| `CKR_PIN_INCORRECT`, `CKR_PIN_EXPIRED`, `CKR_KEY_FUNCTION_NOT_PERMITTED`, key label not found | `ErrProviderDenied` |
| `CKR_ENCRYPTED_DATA_INVALID`, `CKR_ENCRYPTED_DATA_LEN_RANGE`, a bad `p11:` header | `ErrDecryptFailed` |
| anything else | `ErrProviderUnavailable` |

sandboxd runs helpers with `os/exec`. Go's fork-then-exec never calls PKCS#11
in the child, so fork safety is not an issue. The plan records this so a
reviewer does not have to rediscover it.

**Settings.**

| Variable | Meaning |
|---|---|
| `SB_SECRET_PKCS11_MODULE` | Path to the vendor `.so` |
| `SB_SECRET_PKCS11_TOKEN_LABEL` | Token (partition) label; must match exactly one slot |
| `SB_SECRET_PKCS11_PIN_FILE` | User PIN; mode 0400 enforced with the same check as `wrap_key_loader.go:72` |
| `SB_SECRET_PKCS11_KEY_LABEL` | Current key, used for new wraps |
| `SB_SECRET_PKCS11_DECRYPT_KEY_LABELS` | Older keys still allowed for unwrap (rotation) |
| `SB_SECRET_PKCS11_MAX_SESSIONS` | Pool size, default 8 |
| `SB_SECRET_PKCS11_GCM_IV` | `hsm` (default) or `caller` |

**Clusters.** Every node must reach the **same** key, through a network HSM
partition (CloudHSM, Luna, nShield Connect) or the same key imported into each
node's token. Otherwise a backup node cannot unwrap the owner's copy. Boot
cannot detect this. Phase 6 tests it, and the docs state it.

### 3. The wrapped server key

**New setting:** `SB_CREDENTIAL_KEY_CUSTODY=file|wrapped`, default `file`,
which is today's behavior. `wrapped` is allowed only when `SB_SECRET_PROVIDER`
is `awskms`, `vault` or `pkcs11`. It uses that same provider: one key store,
one set of permissions, one log.

**The file** is `SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH`, default
`/var/lib/sandboxd/credential_encryption.key.wrapped`, mode 0600:

```json
{
  "format": 1,
  "provider": "vault",
  "key_ref": "transit/aerolvm-kek",
  "wrapped": "<base64 of Wrap(serverKey)>",
  "check": "<base64 of HMAC-SHA256(serverKey, \"aerolvm-server-key-check/v1\")[:16]>"
}
```

The wrap context is `{"aerolvm.purpose": "server-key", "aerolvm.format": "1"}`.
That keeps a server-key wrap from being swapped with a row DEK.

The `check` field catches a wrong key before the store opens. Without it, a
node that unwrapped the wrong key would fail every decrypt at runtime instead
of refusing to start.

**Boot with `wrapped`:**

1. Build the wrapper from config only (no store). See Phase 1.
2. If `SB_CREDENTIAL_ENCRYPTION_KEY` is set, or a plaintext file exists at
   `SB_CREDENTIAL_ENCRYPTION_KEY_PATH`, **refuse to start**. A plaintext copy
   left behind makes the claim false (decision F1).
3. If the wrapped file exists: unwrap it, verify `check`, then build the
   `Cipher` from the bytes.
4. If no key exists anywhere (first start): generate a key, write **only** the
   wrapped file, then verify it reads back.
5. Unwrapping real data proves the key store works, so this replaces the boot
   canary for this case.

**Failure rule.** If the key store is unreachable at boot, the node cannot
start, because it has no key. That is fail-closed by necessity, not by choice.
Running nodes are unaffected, since the key is in memory. Make one attempt with
a 10-second timeout. `sandboxd.service` already has `Restart=always`
(`packaging/sandboxd.service:16`), so do not add a retry loop. The runbook
names this dependency.

**Migration and operations.** Add a `sandboxd key` subcommand, next to the
existing `egress-gateway` subcommand (`cmd/sandboxd/main.go:79`):

- `sandboxd key wrap`: read the current plaintext key, write the wrapped file
  atomically, verify it reads back, then print the plaintext path for the
  operator to delete. It does not delete the file itself, because secure delete
  on SSD or copy-on-write disks is not something we can promise.
- `sandboxd key rewrap`: unwrap under the old key-store key and wrap under the
  current one. This rotates the key-store key. It is cheap and is the rotation
  auditors usually ask for.
- `sandboxd key verify`: unwrap and check, without starting the daemon.

All cluster nodes share one server key, so wrap once and copy the **wrapped**
file to every node. It is ciphertext, so Ansible vars or a Kubernetes Secret
can carry it. Add an Ansible playbook, `wrap-server-key.yml`, and an installer
flag.

### 4. Tag wrapped DEKs now

Vault ciphertext already starts with `vault:v`. PKCS#11 output starts with
`p11:`, as defined above. AWS KMS blobs are opaque binary, so **untagged means
`awskms`**, the only external provider that exists today. `Unwrap` checks the
tag before calling out. On a mismatch it returns `ErrProviderUnavailable` with
"row wrapped by X; node configured for Y" instead of a bare decrypt failure.
This needs no envelope version bump, because the tag lives inside the wrapper's
own output. Live switching (a decrypt-only previous provider plus a reseal
sweep) can be added later with no format change.

### 5. Concurrency, throttling and restart storms

- **Load.** One `Wrap` per cluster create with secrets. One `Unwrap` per
  open. A node restart opens each secret-bearing sandbox it owns. One more
  `Unwrap` per daemon boot for the server key.
- **Limit in one place.** A `limitedWrapper` decorator in `pkg/secrets` caps
  in-flight calls per node (`SB_SECRET_PROVIDER_MAX_INFLIGHT`, default 8, and
  the PKCS#11 pool uses the same number). It retries `ErrProviderThrottled`
  with jittered backoff inside the caller's context deadline. All three
  providers get it, `awskms` included. This fixes fact 7.
- **Fleet math** at the review bar (2,000 nodes, 100k sandboxes):
  - A rolling restart opens about 50 secret-bearing sandboxes per node. That is
    about 100k unwraps spread over the roll.
  - A simultaneous cold start is capped at 2,000 × 8 = 16k calls in flight.
  - Phase 0 measures what one Vault active node and one CloudHSM partition can
    sustain. The docs publish the sizing rule from that measurement, not from
    vendor claims.
- **No DEK cache** (non-goal above).

### 6. Boot-path latency (CLAUDE.md rule 2)

- **Daemon boot:** one key-store call to unwrap the server key, plus the
  existing canary when custody is `file`.
- **`CreateSandbox`:**
  - Non-cluster creates: no new work.
  - Cluster creates with secrets: no new **calls**. They already make one
    `Wrap` (fact 8); only the backend that answers changes.
  - Phase 0 measures `Wrap` p50 and p99 for each backend from the same AWS
    region, with AWS KMS as the baseline. Do not assume the numbers.
- **First call:** the boot canary or the server-key unwrap opens the TLS
  connection or PKCS#11 session first. The first create does not pay for it.

### 7. Enterprise mode

- Extend `internal/config/config.go:2710`: strict boot is required for **any**
  external provider (`awskms`, `vault`, `pkcs11`), not only `awskms`.
- Enterprise mode with an external provider and `custody=file`: warn in the
  first release, refuse in the next (decision F2). Without wrapping, the
  enterprise "key custody" claim stays false.
- Enterprise mode refuses a Vault token given as an env var. A token file or
  the Agent proxy is required.

### 8. Audit evidence

Each call shows in the key store's own log: Vault audit devices, the HSM audit
log, or CloudTrail. That is the evidence for NIST SP 800-53 SC-12/SC-28 and is
what the docs point auditors to. Do not add a `kek` field to secret audit
events in v1. It is cheap (an `omitempty` field does not change old event
hashes), but nobody has asked for it.

## Coordination with other plans

- **`plans/kubernetes-deployment.md:181`** proposes
  `SB_SECRET_PROVIDER=kubernetes` to back the server key with a Kubernetes
  Secret. Recommendation: drop it. The wrapped server key file, mounted from a
  Secret, does the same job with an external key store behind it, and adds no
  new provider.
- **HSM signing of audit heads** (`plans/secrets-hardening.md:1014`, and
  `plans/open-audit-witness.md` Non-goals) can reuse the PKCS#11 session pool
  from Phase 3. It stays a separate plan.

## Testing

**Offline (`make test`, 85% bar on `pkg/secrets`):**

- **Vault:** an `httptest` fake of Transit encrypt and decrypt. It checks the
  AAD, returns 403/429/503 and sealed responses, and covers token-file reload,
  non-loopback `http://` refusal and namespace headers.
- **PKCS#11:** a narrowed `p11API` interface faked in Go. It covers session
  loss and reopen, pool exhaustion → throttled, the IV modes, label rotation
  and a bad header.
- **Both:** run the existing `testProviderContract`
  (`pkg/secrets/provider_contract_test.go:17`) over `NewKMSProvider` with each
  new wrapper.
- **Server key:** first-start generate, unwrap, `check` mismatch, refusal when
  plaintext is present, refusal with provider `local`, and the boot order in
  `pkg/daemon` (wrapper before `NewCipher` before store open).
- **Config:** a validation table for every new variable and the enterprise
  rules.
- **`limitedWrapper`:** concurrency cap, backoff, context deadline.

**Tag-gated real backends** (a new CI job like `wasm-integration`, not in
`make test`): run `vault server -dev`, `bao server -dev` and SoftHSM2 on the
runner, and run the same contract suite against each.

**Live AWS itest** (operator-run, costs money; see `integration-tests/README.md`):

- `cluster-3-mixed-secrets-vault`: OpenBao on a harness node, with Raft
  storage, TLS and Vault Agent on each node.
- `cluster-3-mixed-secrets-pkcs11`: SoftHSM2 on each node with the **same**
  imported key. This proves the code path, not a network HSM.
- **One operator-gated AWS CloudHSM run** before the docs name CloudHSM. It
  covers the HSM-generated IV and the session limits. CloudHSM bills hourly per
  HSM, so tear down in the same run.
- **New UCs:**
  - boot canary;
  - create with env, registry and mount secrets;
  - failover open on a backup node;
  - key disabled → open denied plus a secret audit event;
  - key store down at boot with `wrapped` → refuses to start, and recovers
    after the key store returns;
  - restart with 50 secret-bearing sandboxes → in-flight cap respected, all
    open;
  - `sandboxd key rewrap` after rotation.

## Docs

- **New page** `key-custody.mdx` ("Use your own key store"). It is a top-level
  feature, so it gets its own page per CLAUDE.md, via `/add-docs-page`. Its
  examples are operator config, so like `cli.mdx` it ends with a "Same thing
  from the SDK" section: a five-tab create with env, showing that SDK code does
  not change.
- **Update:**
  - `cluster-secrets.mdx`: provider table (`:31-33`), steps (`:119-121`), and
    a general "startup check" section;
  - `enterprise/architecture.mdx:138`, `:173-178`;
  - `enterprise/hardening.mdx` HV-5 and HC-5;
  - `enterprise/security-controls.mdx` DP-5;
  - `enterprise/audit-evidence.mdx` SC-12;
  - `enterprise/responsibility.mdx:36`;
  - `engineering-secret-handling.mdx:180`, `:224`;
  - `setup/config-defaults.md:64-66`, `:96`, `:192`;
  - `setup/runbooks/secrets-and-audit.md:89`, `:768`.
- **Rule:** name only vendors that passed Phase 6. Everything else is "any HSM
  with PKCS#11 v2.40 AES-GCM; not yet tested".

## Phases

One PR per phase, stacked, with nothing merged until the whole stack is green.

| Phase | What | Effort |
|---|---|---|
| 0 | **Spike, no product code.** Test Vault and OpenBao decrypt with wrong AAD. Test GCM IV behavior on SoftHSM2 and CloudHSM. Choose miekg or crypto11. Measure p50, p99 and throughput for AWS KMS, Vault and CloudHSM from one region. Record the results in this file. | S (plus about 2 hours of CloudHSM) |
| 1 | **Seam split.** `secrets.NewWrapper(ctx, opts)` builds the wrapper from config with no store, and `NewProvider` takes it. Add the `limitedWrapper` decorator, the provider tags, the general strict-boot and canary, and the config validation. No behavior change for `local` or `awskms`. | S |
| 2 | The `vault` wrapper and its tests. | M |
| 3 | The `pkcs11` wrapper, session pool and tests. | M |
| 4 | Wrapped server key: boot order in `pkg/daemon`, `sandboxd key wrap/rewrap/verify`, the Ansible playbook and the installer flag. | M |
| 5 | Enterprise rules, the docs page and updates, config-defaults and the runbook. | S |
| 6 | The tag-gated CI job, the live itest scenarios, the CloudHSM run, and an Outcome section here. | M (AWS time) |

Phase 1 also rewrites the reject at `internal/config/config.go:2599-2602` and
the comment at `pkg/secrets/factory.go:38-40`. The `vault` value keeps
refusing to boot until Phase 2 lands in the same stack.

## Decisions needed

**Founder:**

- **F1.** With `custody=wrapped`, refuse to start while a plaintext key is
  still present? *Recommend yes.* It is the only way the claim is true.
- **F2.** Enterprise mode with an external provider: make `wrapped` required?
  *Recommend:* warn for one release, then refuse.
- **F3.** Which HSM to certify first? *Recommend AWS CloudHSM*, because the
  test stack is already on AWS. Thales Luna or Entrust nShield need a vendor or
  customer dev partition, so do them when a customer brings one.

**Eng review:**

- **E1.** Vault auth limited to a token file and the Agent proxy in v1?
  *Recommend yes.*
- **E2.** Thin Vault client instead of `hashicorp/vault/api`? *Recommend thin.*
- **E3.** Ship the PKCS#11 key-wrap-pad fallback? *Recommend:* only if Phase 0
  finds a target HSM without GCM.
- **E4.** Is untagged = `awskms` the right legacy rule? Check that no other
  wrapper has produced rows in the field. FakeKMS is test-only.
- **E5.** Put `limitedWrapper` defaults (8 in flight, backoff ceiling) in
  config now, or hard-code them until measurements exist?

## Follow-ups (not in this plan)

- **F-R1:** a rewrap sweep (Transit `rewrap`; PKCS#11 old label → new label),
  so operators can retire old key versions.
- Live provider switching: a decrypt-only previous provider plus a reseal.
- Server key (data key) rotation: add a key ID to the `Cipher` format, then
  reseal.
- GCP Cloud KMS, Azure Key Vault and KMIP wrappers, each on customer demand.
- HSM signing of audit heads.
