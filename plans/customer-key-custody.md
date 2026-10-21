# Customer key custody: HashiCorp Vault and PKCS#11 (HSM) key providers

Status: **DRAFT 2026-10-20**. CEO review done 2026-10-20 (SELECTIVE EXPANSION;
decisions in "CEO review" at the end, folded into the sections above). Next
step: `/plan-eng-review`. Open questions and the phase each one blocks are in
"Decisions needed". Nothing here is built.

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
   - **every sandbox's toolbox token**, the credential sandboxd uses to reach
     the in-sandbox agent. It is sealed on write and opened on **every**
     `Store.Get` (`internal/store/store.go:2191-2213`), so exec, files and
     sessions all need the server key;
   - plaintext env and toolbox tokens left by old releases, sealed at store
     open (`migrateLegacyPlaintextSecrets`, `internal/store/store.go:1217`),
     and old env ciphertext re-sealed with AAD
     (`internal/store/env_binding_migration.go:82`);
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
10. **Clusters copy the plaintext key between machines.** `cluster-init.sh`
    writes `SB_CREDENTIAL_ENCRYPTION_KEY=<plaintext>` into
    `/etc/sandboxd/cluster.env` (`scripts/cluster-init.sh:446`) and tars the
    key file into `aerolvm-cred-bundle.tar.gz` (`:411-421`), which the
    operator copies to each joiner. `cluster-join.sh` extracts it and writes
    the same env line (`scripts/cluster-join.sh:380`, `:417`). The Terraform
    bootstrap runs `cluster-init.sh` with no custody flag and uploads the
    plaintext bundle to `s3://<bundle_bucket>/aerolvm-cred-bundle.tar.gz` for
    joiners to download (`Terraform/templates/bootstrap.sh.tftpl:243-265`,
    `:425-456`). So the key lives in up to five places: the key file, the env
    var, `cluster.env`, every copy of the bundle, and the S3 bundle object.

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
- Every unwrap is a call your key store can log and deny. If you disable or
  delete the key (Design §10), every node that can reach your key store stops
  everything AerolVM does with your stored data within about 15 minutes, with
  no restart: no creates, no exec or file access through the AerolVM API or
  SSH gateway, no opened secrets, and open SSH, terminal and exec streams are
  closed. Running sandboxes are not killed, but cannot be managed. **One
  exception:** a running sandbox's own public route (`{id}.{domain}`) reaches
  the agent inside it directly, so whoever already holds that sandbox's
  token (the E2B SDK, for example) can still use it until the sandbox stops.
  Nothing on that path uses your key (CEO-E2D). A node that cannot reach your key store at all keeps its key until
  it restarts, and then cannot start. Rows sealed with that key become
  unreadable for good once the key is **deleted**; a **disabled** key makes
  them unreadable until you re-enable it. Deletion is crypto-shredding, and
  it is a feature: it is how you revoke AerolVM's access for good. Removing
  a permission instead of the key takes effect at the next restart.

**It does not cover:**

- **Software tokens.** SoftHSM2 keeps its token store and PIN on the same
  disk, so a stolen disk does decrypt. It is a test backend only; enterprise
  mode refuses a PKCS#11 slot that is not a hardware slot (Design §2).

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
  of audit heads is its own follow-up (`plans/secrets-hardening.md:1014`),
  deferred at CEO review (CEO-E6) to the TODOS.md entry "HSM signing of audit
  chain heads". The PKCS#11 session code here can be reused for both later.
- **Shared tokens and credentials.** This covers the gossip key, PAT,
  audit-ingest token, webhook HMAC key and the upstream (AOCR) wrap key. They
  are credentials, not data-encryption keys. Operators can already source them
  from Vault with Vault Agent templates.
- **Rotating the server key itself.** The `Cipher` format has no key ID, so
  rotating the data key means resealing every row. Rotating the **key-store
  key that wraps it** is in scope and cheap (see "Rotation").
- **Live provider switching between external providers.** `awskms` →
  `vault`/`pkcs11` and external → external stay unsupported in v1. Rows get
  tagged now so a later tool needs no format change. Moving from `local` to
  any external provider **is** supported (Design §12, CEO-M1).
- **KMIP, GCP Cloud KMS and Azure Key Vault.** Each would be one new wrapper on
  the same seam. GCP and Azure were deferred at CEO review (CEO-E5) to the
  TODOS.md entry "GCP Cloud KMS and Azure Key Vault key providers", with
  triggers: the K8s plan's GKE phase, or a named Azure customer. KMIP waits for
  a customer.
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
`deletion_allowed=false`, so the key cannot be deleted by accident. Revoking
on purpose flips `deletion_allowed` to true first (Design §10). The node's
permissions are in "Permissions each backend needs" below.

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
for a customer who cannot run Vault Agent. sandboxd never reads the
`VAULT_TOKEN` environment variable, so a token cannot reach it through the
unit's environment by accident.

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
| 400, Transit key not found (deleted) | `ErrKeyRevoked` (new, Design §10) |
| 400, ciphertext version below `min_decryption_version` | `ErrKeyVersionRetired` (new; stale, not a revoke) |
| 403, still 403 after one token reload | `ErrProviderDenied` |
| 429 | `ErrProviderThrottled` |
| 5xx, sealed, connection refused or timeout | `ErrProviderUnavailable` |

**Audit correlation (CEO-E3).** Every Transit call sends
`X-Aerol-Correlation-ID`, taken from `auditlog.CorrelationIDFromContext(ctx)`
(`pkg/auditlog/correlation.go:34`), so a Vault audit entry joins to the exact
sandboxd secret audit event. Calls with no request behind them (the boot
unwrap, the re-check in Design §10 and the sweep in Design §11) send a fixed
`aerolvm-background:<boot|recheck|sweep>:<node-id>` instead, so they are
recognisable in Vault's log but join to no event. Vault records a request header only when it is
listed under its audited request headers, so `key-custody.mdx` documents that
one setting. Phase 0 confirms the setting on Vault and OpenBao. This matches
AWS KMS, where CloudTrail already shows the bound encryption context. PKCS#11
has no equivalent, and the docs say so.

**Rotation.** Transit versions its keys itself. Ciphertext carries
`vault:vN:`, new wraps use the latest version, and old rows still decrypt
until the operator raises `min_decryption_version`. Before raising it, the
rewrap sweep (Design §11, CEO-E4) must move live rows to the new version.
Transit's `rewrap` endpoint does this without exposing the DEK to sandboxd,
if it accepts `associated_data` (Phase 0). If it does not, the sweep
decrypts and re-encrypts inside sandboxd, as an open does.

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
covers all sessions. Keep a bounded pool of sessions sized as the
foreground cap plus the background slots (Design §5), so background work
never takes a session a create needs. After a session is reopened for
`CKR_DEVICE_REMOVED` or `CKR_TOKEN_NOT_PRESENT` (an HSM HA failover, for
example), log in again, treating `CKR_USER_ALREADY_LOGGED_IN` as success;
`CKR_USER_NOT_LOGGED_IN` also triggers one re-login and retry. These return codes reopen the session and retry once:
`CKR_SESSION_HANDLE_INVALID`, `CKR_SESSION_CLOSED`, `CKR_DEVICE_REMOVED` and
`CKR_TOKEN_NOT_PRESENT`. After that, errors map to the existing classes:

| PKCS#11 result | Error |
|---|---|
| `CKR_SESSION_COUNT`, `CKR_DEVICE_MEMORY`, pool wait timeout | `ErrProviderThrottled` |
| `CKR_KEY_FUNCTION_NOT_PERMITTED` (decrypt turned off), or the **current** label (`SB_SECRET_PKCS11_KEY_LABEL`) not found | `ErrKeyRevoked` (new, Design §10) |
| `CKR_PIN_INCORRECT`, `CKR_PIN_EXPIRED`, `CKR_PIN_LOCKED` | `ErrProviderDenied` |
| a label in `SB_SECRET_PKCS11_DECRYPT_KEY_LABELS` not found, while the current label still exists | `ErrKeyVersionRetired` |
| a decrypt-only label not found **and** the current label not found | `ErrKeyRevoked` (so a revoke during a rotation window still trips) |
| a `p11:` header naming a label in neither setting | `ErrDecryptFailed` ("wrapped under an unknown key label") |
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
| `SB_SECRET_PKCS11_PIN_FILE` | User PIN; group and other permission bits refused, with the same check as `wrap_key_loader.go:72` (0400 and 0600 pass) |
| `SB_SECRET_PKCS11_KEY_LABEL` | Current key, used for new wraps |
| `SB_SECRET_PKCS11_DECRYPT_KEY_LABELS` | Older keys still allowed for unwrap (rotation) |
| `SB_SECRET_PKCS11_GCM_IV` | `hsm` (default) or `caller` |

**Software tokens.** At boot, `C_GetSlotInfo` reports whether the slot is
hardware (`CKF_HW_SLOT`). SoftHSM2 is not. Enterprise mode refuses a
non-hardware slot; outside enterprise mode it logs a warning, and
`sandboxd key status` shows `software token`. Phase 0 confirms CloudHSM sets
the flag.

**Clusters.** Every node must reach the **same** key, through a network HSM
partition (CloudHSM, Luna, nShield Connect) or the same key imported into each
node's token. Otherwise a backup node cannot unwrap the owner's copy. Boot
cannot detect this. Phase 6 tests it, and the docs state it.

### Permissions each backend needs

Covers creates, opens, the boot unwrap, the re-check (Design §10) and the
sweep (Design §11). Nothing else.

| Backend | Grant |
|---|---|
| `awskms` | `kms:Encrypt`, `kms:Decrypt` and `kms:DescribeKey` (to tell a pending deletion from an outage, Design §10) on the one key. No `ReEncrypt`: AWS rotates in place, so there is no AWS sweep (Design §11). |
| `vault` | `update` on `<mount>/encrypt/<key>`, `<mount>/decrypt/<key>` and `<mount>/rewrap/<key>`; `read` on `<mount>/keys/<key>` (latest version for the sweep). |
| `pkcs11` | user login on the token; the key object with `CKA_ENCRYPT` and `CKA_DECRYPT`; the decrypt-only labels with `CKA_DECRYPT`. |

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

**Config check.** Today cluster mode refuses to boot unless the plaintext
key is set or its file exists (`internal/config/config.go:2573-2580`), which
would contradict step 2 below. With `custody=wrapped` that check accepts the
wrapped file instead, and Phase 1 changes it with a row in the config
validation table.

**Boot with `wrapped`:**

1. Build the wrapper from config only (no store). See Phase 1.
2. If `SB_CREDENTIAL_ENCRYPTION_KEY` is set, or a plaintext file exists at
   `SB_CREDENTIAL_ENCRYPTION_KEY_PATH`, **refuse to start**. A plaintext copy
   left behind makes the claim false (decision F1).
3. If the wrapped file exists: unwrap it, verify `check`, then build the
   `Cipher` from the bytes.
4. If no key exists anywhere, the daemon generates one **only** in single-node
   mode (cluster mode off) **and** when `state.db` does not exist yet. Write
   only the wrapped file, then verify it reads back. In cluster mode the
   daemon never generates a key: the seed's key comes from `cluster-init.sh`
   running `sandboxd key wrap --generate`, and every node, seed included,
   refuses to start without the wrapped file ("copy
   credential_encryption.key.wrapped from the seed"). `SB_CLUSTER_BOOTSTRAP`
   stays in `cluster.env` for good (`scripts/cluster-init.sh:436`), so it
   cannot be the test; otherwise a seed restored without its wrapped file
   would mint a new key, split the cluster and orphan its own rows.
5. Unwrapping real data proves the key store works, so this replaces the boot
   canary for this case.

**Failure rule.** If the key store is unreachable at boot, the node cannot
start, because it has no key. That is fail-closed by necessity, not by choice.
Running nodes are unaffected, since the key is in memory. Make one attempt with
a 10-second timeout. `sandboxd.service` already has `Restart=always`
(`packaging/sandboxd.service:16`), so do not add a retry loop. The runbook
names this dependency.

**Migration and operations.** Add a `sandboxd key` subcommand, next to the
existing `egress-gateway` subcommand (`cmd/sandboxd/main.go:79`). It runs
outside systemd, so it loads the same env files the unit gives the daemon
(`packaging/sandboxd.service:9`, `scripts/cluster-init.sh:467`): `--env-file`,
default `/etc/sandboxd/sandboxd.env` then `/etc/sandboxd/cluster.env`, then
the process environment on top. It never opens the database.

- `sandboxd key wrap`: read the current plaintext key, write the wrapped file
  atomically, verify it reads back, then print the plaintext path for the
  operator to delete. It does not delete the file itself, because secure delete
  on SSD or copy-on-write disks is not something we can promise.
- `sandboxd key wrap --generate`: make a fresh key and write only the wrapped
  file. Refuses if any key, plaintext or wrapped, already exists. In cluster
  mode it also needs `--seed`, an empty raft directory and no `state.db`, so
  it cannot run on a joiner by mistake (Section 3, S5). Used by
  `cluster-init.sh` and `install.sh`.
- `sandboxd key rewrap`: unwrap the **server-key file** under its current
  key-store key and wrap it under the newest one. Rows are not touched; the
  daemon's sweep (Design §11) rewraps them at its next boot or cadence.
- `sandboxd key verify`: unwrap and check, without starting the daemon.
- `sandboxd key status`: the custody report (Design §9).
- `sandboxd key unwrap --to-file --i-understand-plaintext` (CEO-R1): the
  rollback to `custody=file`. At the next boot the daemon sees the custody
  changed and writes a `key_custody_changed` audit event (Section 3, S7). Unwraps through the key store, writes the key
  file at mode 0600, refuses without the acknowledgement flag, and prints that
  the custody claim no longer holds for this node. The operator then sets
  `SB_CREDENTIAL_KEY_CUSTODY=file` and restarts. The custody report and the
  `SandboxdServerKeyPlaintext` alert show the node as plaintext again.

All cluster nodes share one server key, so wrap once and copy the **wrapped**
file to every node. It is ciphertext, so the cred bundle, Ansible vars or a
Kubernetes Secret can carry it.

**Every place the plaintext key lives today** (fact 10, five places) must
change, or the claim is false:

| Where | Today | With `custody=wrapped` |
|---|---|---|
| Key file (`SB_CREDENTIAL_ENCRYPTION_KEY_PATH`) | written by `loadOrGenerateKey` | never written; boot refuses if present (F1) |
| Env var `SB_CREDENTIAL_ENCRYPTION_KEY` | read at boot | boot refuses if set (F1) |
| `/etc/sandboxd/cluster.env` | `cluster-init.sh:446` and `cluster-join.sh:417` write `SB_CREDENTIAL_ENCRYPTION_KEY=<plaintext>` | scripts write `SB_CREDENTIAL_KEY_CUSTODY=wrapped` and no key line |
| `aerolvm-cred-bundle.tar.gz` | `cluster-init.sh:411-421` tars the plaintext key file; `cluster-join.sh:380` extracts it | bundle carries `credential_encryption.key.wrapped` only; join installs it |
| S3 bundle object (Terraform) | `bootstrap.sh.tftpl:243-265` uploads the plaintext bundle; joiners fetch it (`:425-456`) | a `key_custody` Terraform variable passes `--key-custody wrapped` through; the object then holds only the wrapped file |

`cluster-init.sh` gains `--key-custody wrapped`, which calls
`sandboxd key wrap --generate` so the seed never writes a plaintext key.
`install.sh` gains the same flag for single-node installs. For an existing
cluster, the runbook is: `sandboxd key wrap` on one node, copy the wrapped
file to all nodes, remove the key line from `cluster.env`, delete old cred
bundles and overwrite or delete the S3 bundle object, restart node by node. The F1 refusal catches a forgotten
`cluster.env` line.

**Backups.** `scripts/sandboxd-backup.sh` copies only `state.db` and the raft
directory today. Add the wrapped file to the backup and to
`scripts/sandboxd-restore.sh`. The restore needs the key store reachable,
which the runbook states. After a key version is retired (Design §11), an
older backup's wrapped file no longer opens, so the runbook says to take a
fresh backup after every retirement.

### 4. Tag wrapped DEKs now

Vault ciphertext already starts with `vault:v`. PKCS#11 output starts with
`p11:`, as defined above. Untagged bytes are either a `local` row (DEK wrapped
under the server key) or an `awskms` row (opaque KMS blob). An untagged row is
opened with the server key first, then with AWS KMS when that is the
provider (Design §12). `Unwrap` checks the tag before calling out. On a mismatch it returns `ErrProviderUnavailable` with
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
  - A simultaneous cold start is capped at 2,000 × 8 = 16k foreground calls in
    flight (20k with background slots).
  - Phase 0 measures what one Vault active node and one CloudHSM partition can
    sustain. The docs publish the sizing rule from that measurement, not from
    vendor claims.
- **Background work never blocks a create.** The re-check (Design §10) and
  the sweep (Design §11) use a separate, smaller budget (2 slots [estimated])
  inside `limitedWrapper`, so a create's `Wrap` never waits behind them. The
  PKCS#11 session pool is sized foreground plus background (8 + 2), so the
  cold-start bound in the fleet math above becomes 2,000 × 10 = 20k calls in flight.
- **Sweep load after a rotation.** Every copy on every node is rewrapped, and
  on Vault every call lands on one active node. The sweep starts after a
  random delay of up to one cadence period and runs only on the 2 background
  slots, which caps it at 2 × 2,000 = 4k in flight fleet-wide [estimated].
  CEO-E4a sets the cadence with Phase 0's Vault throughput in hand.
- **No DEK cache** (non-goal above).

### 6. Boot-path latency (CLAUDE.md rule 2)

- **Daemon boot:** one key-store call to unwrap the server key, plus the
  existing canary when custody is `file`.
- **`CreateSandbox`:**
  - Non-cluster creates: no new work.
  - Cluster creates with secrets: no new **calls**. They already make one
    `Wrap` (fact 8); only the backend that answers changes.
  - **New wait, called out:** that `Wrap` now goes through `limitedWrapper`.
    It can queue behind restart and failover opens in the foreground slots,
    and it can back off on throttling, for `awskms` too. One foreground slot
    is reserved for create-path wraps [estimated], the wait is bounded by the
    caller's deadline, and Phase 0 measures it under a restart storm. The PR
    that adds the limiter calls this out under "Sandbox boot impact".
  - Phase 0 measures `Wrap` p50 and p99 for each backend from the same AWS
    region, with AWS KMS as the baseline. Do not assume the numbers.
- **First call:** the boot canary or the server-key unwrap opens the TLS
  connection or PKCS#11 session first. The first create does not pay for it.
- **Background work, off the create path:** the boot-time sweep and the
  5-minute re-check run on their own `limitedWrapper` budget (Design §5), so
  they add no wait to `CreateSandbox`. The boot sweep runs after the API is
  serving, not before.

### 7. Enterprise mode

- Extend `internal/config/config.go:2710`: strict boot is required for **any**
  external provider (`awskms`, `vault`, `pkcs11`), not only `awskms`.
- Enterprise mode with an external provider and `custody=file`: warn in the
  first release, refuse in the next (decision F2). Without wrapping, the
  enterprise "key custody" claim stays false.
- Enterprise mode refuses a PKCS#11 slot that is not a hardware slot
  (Design §2).

### 8. Audit evidence

Each call shows in the key store's own log: Vault audit devices, the HSM audit
log, or CloudTrail. That is the evidence for NIST SP 800-53 SC-12/SC-28 and is
what the docs point auditors to. Do not add a `kek` field to secret audit
events in v1. It is not as cheap as it looks: the event hash covers the JSON
in field order, so an older binary in a mixed-version cluster drops the
unknown field, recomputes a different hash and fails strict boot verify. A new
field has to be appended, `omitempty`, and written only once every member's
gossip feature version supports it (`pkg/auditlog/hash.go`,
`pkg/auditlog/event.go`). Nobody has asked for it.

### 9. Key custody report (CEO-E1)

`sandboxd key status` prints one row per key class and where it lives. It is
read-only, opens no database and makes no key-store call. It shows the
server-key file's wrapped version (`vault:vN`, or its `p11:` label). With
`--check` it also unwraps that file once and, on Vault, reads the latest key
version, so it can say whether the file is stale. The count of stale
**rows** lives only in the running daemon's `aerolvm_key_rows_stale` gauge
(Design §11).

| Class | Possible answers |
|---|---|
| Server key | `customer key store (wrapped)`, `plaintext file`, `env var` |
| Cluster-secret DEKs | `awskms`, `vault`, `pkcs11`, `local (server key)` |
| Egress-inspection CA key | follows the server key |
| Node TLS key, gossip key, PAT, audit-ingest token, upstream wrap key | `plaintext file` or `env var` (out of scope; listed so the report never overstates) |

The same answers feed a `aerolvm_key_custody{class,custody,enterprise}` gauge
(published once at boot through the existing expvar/OTEL exporter in
`internal/service/metrics.go`). A new Prometheus rule in `setup/prometheus/`,
`SandboxdServerKeyPlaintext`, fires when `enterprise="true"` and the
server key's `custody` is not `wrapped`. Its runbook entry goes in
`setup/runbooks/secrets-and-audit.md`.

### 10. Revocation within minutes (CEO-E2)

**Goal.** A customer who revokes the key cuts AerolVM off within a stated
bound, without restarting nodes.

**Re-check.** With `custody=wrapped`, every
`SB_SECRET_PROVIDER_RECHECK_INTERVAL` (default 5 minutes [estimated], with
jitter), each node **unwraps its stored wrapped server key again** and
compares the `check` value. This uses real data, not a fresh canary, so it
also catches a retired version still in use (reported as stale, not as a
revoke). It runs on the background budget (Design §5). Cost:
one key-store call per node per interval, about 7 calls per second across
2,000 nodes [estimated].

**Only deliberate signals count as a revoke.** Phase 1 adds an
`ErrKeyRevoked` sentinel (and `ErrKeyVersionRetired` for stale versions) to
`pkg/secrets/errors.go`. Each re-check result is sorted into ok, unavailable,
throttled, denied, retired or **revoked**:

| Backend | Revoked means | Not a revoke (alert only) |
|---|---|---|
| `awskms` | `DisabledException`, `NotFoundException`, and `KMSInvalidStateException` **only** when `DescribeKey` reports `PendingDeletion`. Today these map to Unavailable and Denied (`pkg/secrets/awskms.go:103-113`); Phase 1 moves them to `ErrKeyRevoked`. | `AccessDeniedException` (IAM or key-policy drift); `KMSInvalidStateException` in any other key state, such as a disconnected custom key store; `KeyUnavailableException` |
| `pkcs11` | key label gone, or `CKR_KEY_FUNCTION_NOT_PERMITTED` (decrypt turned off on the key) | PIN errors, session or device errors |
| `vault` | the Transit key is not found (deleted) | 403 (a revoked policy and an expired Agent token look the same); a retired version (stale, `ErrKeyVersionRetired`) |

So the documented revoke procedure is: **AWS KMS**, disable the key or
schedule deletion; **HSM**, destroy **every** label, current and decrypt-only, or clear
`CKA_DECRYPT` on each (a server-key file still on an old label would
otherwise pass the re-check);
**Vault**, set `deletion_allowed=true` on the Transit key, then delete it.
Removing a policy or IAM grant still takes effect only at the next restart,
and the docs say so.

Why not "retire the version" for Vault: Vault refuses a
`min_decryption_version` above the latest version, so retiring needs a rotate
first, and the sweep (Design §11) running between the rotate and the retire
would move the server-key file onto the new version and silently undo the
revoke. A delete cannot be undone by the sweep. Eng review confirms (CEO-E2c).

**The mechanism.** The store and the service share one `*secrets.Cipher`
(`pkg/daemon/daemon.go:155-160`, `internal/service/service.go:736`). The
`Cipher` holds its AEAD behind an atomic pointer. `Revoke()` swaps it to nil,
and every `Encrypt` and `Decrypt` then returns `ErrKeyRevoked`. One call
therefore covers both holders. Recovery (CEO-E2a) swaps a new AEAD in. The
`KMSProvider` path needs nothing extra: every open already calls the key
store.

**On a revoke.** After `SB_SECRET_PROVIDER_REVOKE_AFTER` consecutive revoked
results (default 3, so about 15 minutes [estimated]), the node:

- **stops processing the customer's data (full stop, CEO-E2R).** It calls
  `Cipher.Revoke()`, drops its in-memory egress-inspection CA
  (`egress.InspectCA`, loaded at `internal/service/egress_inspect.go:117`),
  and stops opening cluster-secret copies. The CA key also lives in the
  **egress gateway**, a separate process with its own systemd unit
  (`packaging/aerolvm-egress-gateway.service`), which gets it through
  `set_inspect_ca` (`internal/egress/proto.go:38`,
  `internal/egress/gatewayd/daemon.go:151`) and has no way to clear it. Phase 4
  adds a `clear_inspect_ca` op that sandboxd sends on revoke. The gateway also
  drops the CA once sandboxd has been gone longer than the revoke bound
  (about 15 minutes; sandboxd sends the bound in the `set_inspect_ca`
  message, so the gateway needs no setting of its own), so a sandboxd that can no longer boot cannot leave the
  key behind, while an ordinary sandboxd restart (seconds) does not break
  inspected egress; Go cannot promise memory is
  zeroed, so the docs say "dropped", not "wiped";
- fails every operation that reads sealed data with `ErrKeyRevoked` ("key
  revoked by the key store"). Because every sandbox's toolbox token is sealed
  with the server key (fact 3), that is almost everything: create (with or
  without secrets), exec, files, sessions and recreate. Inspected egress from
  running sandboxes fails closed, since no leaf certificates can be minted;
- closes open SSH gateway sessions, terminals and exec streams proxied
  through this node. They hold a toolbox token opened before the revoke
  (`pkg/sshgateway/gateway.go:394`), so leaving them open would contradict the
  claim;
- leaves running sandboxes running. They are not killed (`Store.List` does not
  open toolbox tokens), but nothing can manage them through this node until
  the key returns (CEO-E2a) or they are recreated on a node that still has a
  key. Their own public toolbox routes stay up (CEO-E2D): those go Caddy →
  toolboxd (`pkg/caddy/client.go:216-237`), which checks only the bearer token
  (`cmd/toolboxd/main.go:567-577`), and some clients already hold it
  (`pkg/api/e2b/handlers.go:1153-1158`). The docs name this exception;
- reports `degraded` from `Service.Health`. Health still answers 200 today
  (TODOS.md "A partitioned node keeps serving"), so the docs do not promise
  that the ingress stops routing;
- writes a `key_revoked` secret audit event (a new `Kind` value, not a new
  field, so the hash rollout rule in Design §8 does not apply), sets a gauge
  and fires a critical alert, `SandboxdKeyRevoked`.

With `custody=file` there is no wrapped key to re-check. Revoking then only
blocks new cluster-secret opens, which already call the key store, and local
rows stay readable. The custody report (§9) and the docs make that gap
visible.

**Pending for eng review** (accepted scope, open implementation choices):

- **CEO-E2a.** After the customer re-enables the key, does the node recover
  on its own at the next good re-check, or only after a restart?
- **CEO-E2b.** Should a revoked node tell placement to stop sending it creates
  that carry secrets, or is failing closed with a clear error enough?
- **CEO-E2c.** Confirm the defaults (5 minutes × 3) and the exact Vault error
  text for a retired version (Phase 0).

### 11. Rewrap sweep (CEO-E4)

**Why.** Rotating a key is free: Transit adds a version, a new PKCS#11 label
becomes current, AWS KMS rotates in place. **Retiring** the old version is
not, because every row sealed earlier still wraps its DEK under it. The
sweep moves stored keys onto the current version so retirement is safe.

**What it rewrites.** Only the `WrappedKey` bytes inside each envelope. The
payload AAD (`PayloadAADBound`, `pkg/secrets/envelope.go`) does not cover the
wrapped key, so the payload, the seal generation and the ref stay the same.

| Backend | How a stale row is found | How it is rewrapped |
|---|---|---|
| `vault` | `vault:vN:` prefix with N below the latest version | Transit `rewrap` with `associated_data` (Phase 0); else decrypt and re-encrypt in sandboxd |
| `pkcs11` | label in the `p11:` header is not `SB_SECRET_PKCS11_KEY_LABEL` | decrypt under the old label, encrypt under the new, inside one session |

AWS KMS has no sweep: it rotates key material in place and never retires it,
and a changed key id is a provider switch, which v1 does not support.

**Where it runs.** Inside the daemon, never in a second process: SQLite has
one writer per process (`MaxOpenConns=1`), and a CLI opening the database
alongside the daemon would break that. It runs at boot and then on a cadence
(CEO-E4a), on the background budget of `limitedWrapper` (Design §5), and
also rewraps the node's own server-key file. With the daemon stopped,
`sandboxd key rewrap` covers the server-key file, and the rows wait for the
next boot sweep.

**Ownership and handoffs.** The sweep is a new writer over sealed rows, so it
must lose every race it could win wrongly. It reads the row without a lock,
calls the key store, then takes `lockSecretSandboxOps`
(`internal/service/seal_distribute.go:78`) only around a conditional `UPDATE`
that matches the same ref, generation and sealed bytes it read
(compare-and-swap). It never holds the lock across the key-store call and
never upserts (Section 4). The paths it can meet: a new `Put` (new generation, already
current, so skip), a reseal from repair, an incoming peer copy, delete and
tombstone, and reseal retirement. Each node rewraps only its own copies; no
fan-out, because every node reaches the same key store.

**Progress and retirement.** A `aerolvm_key_rows_stale` gauge per node
counts stale rows **plus the node's server-key file**. It is a daemon metric;
`sandboxd key status --check` shows only the server-key file's part. The documented procedure: rotate, wait until
**every member in cluster membership** reports 0 (a node that is down
reports nothing, and that is not a 0), then retire the old version. A node
whose server-key file is still on a retired version cannot boot, and
`sandboxd key rewrap` cannot save it once the version is gone, so the
runbook says to bring every node up before retiring. A
version retired early is **not** a revoke (Design §10): rows still on it fail
with `ErrKeyVersionRetired`, so opens for those sandboxes fail on that node,
the custody report counts them, and an alert fires
(`SandboxdKeyVersionRetiredInUse`). The docs warn about it.

**Pending for eng review:**

- **CEO-E4a.** Cadence and trigger: boot plus daily, or also on demand?
- **CEO-E4b.** Confirm nothing compares sealed bytes across nodes (fan-out
  ACK, holder repair). After a rewrap, two holders of the same generation have
  different bytes. A static search on 2026-10-20 found no such comparison in
  `internal/service`; eng review confirms.

### 12. Adopting a provider on an existing cluster (CEO-M1)

Most clusters run `local`. Its rows wrap each DEK under the server key with
recipient binding (`pkg/secrets/envelope.go:130`, `:229`). After the switch:

- **Opening an untagged row.** The node first tries the server key with the
  local rules (`KeyAADBound`, the same recipient check as `LocalProvider`).
  GCM authenticates the attempt, so a wrong guess fails cleanly. If that
  fails and the provider is `awskms`, it tries AWS KMS (an untagged
  `awskms` row). This replaces "untagged means `awskms`" (§4, E4) with
  "untagged means local, else `awskms`".
- **Converting.** The sweep (§11) gains a fourth source format: a local row is
  unwrapped with the server key and wrapped under the new provider, under the
  same compare-and-swap. Payload, generation and ref stay the same. Recipients
  stay recorded for fan-out (the external path ignores them for access).
- **Progress.** `aerolvm_key_rows_stale` counts local rows too, so "0 on every
  member" means the switch is complete.
- **Revoke.** A revoked `Cipher` cannot open local rows either, which matches
  the full stop.
- **Still unsupported:** `awskms` → `vault`/`pkcs11`, and any external →
  external switch (Non-goals).
- **Known limit, rolling switch.** A node not yet switched cannot open rows
  sealed by a switched node. Sandboxes created during the rolling restart can
  lack a usable failover copy on unswitched nodes until those nodes switch.
  The runbook keeps the window short (switch config on every node, then a
  quick rolling restart). Eng review may narrow it (E9).

## Coordination with other plans

- **`plans/kubernetes-deployment.md:181`** proposes
  `SB_SECRET_PROVIDER=kubernetes` to back the server key with a Kubernetes
  Secret. Recommendation: drop it. The wrapped server key file, mounted from a
  Secret, does the same job with an external key store behind it, and adds no
  new provider.
- **HSM signing of audit heads** (`plans/secrets-hardening.md:1014`, and
  `plans/open-audit-witness.md` Non-goals) can reuse the PKCS#11 session pool
  from Phase 3. Deferred to its TODOS.md entry (CEO-E6).
- **Cluster placement.** If eng review answers CEO-E2b "yes" (a revoked node
  tells placement to stop sending it creates), that change touches
  `internal/cluster` and falls under CLAUDE.md rule 6: a regression test next
  to the changed file and a cluster-correctness call-out in the PR.

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
- **`limitedWrapper`:** concurrency cap, backoff, context deadline, and that
  background calls never take the foreground slots.
- **Error classes:** each backend's table (Design §1, §2, §10) maps to the
  right sentinel, including the `awskms` change for `Disabled` and
  `NotFound`, `KMSInvalidState` counted as a revoke only with
  `PendingDeletion` from `DescribeKey`, and the PKCS#11 rotation-window case
  (both labels gone → revoked).
- **Config:** cluster mode with `custody=wrapped` boots with the wrapped file
  and no plaintext key (`config.go:2573-2580` rewritten).
- **API errors (Section 2):** each provider class returns 503 with its stable
  code, `Retry-After` on throttling; no log line contains a request or
  response body from the key store.
- **Custody report (§9):** a table test over config combinations for
  `sandboxd key status` and the gauge labels, including `software token`.
- **Revocation (§10):** the classifier per backend; N consecutive revokes
  trip, a non-revoke in between resets the count, a Vault 403 never trips;
  the shared `Cipher` stops working for both the store and the service; the
  `key_revoked` event kind; and recovery per CEO-E2a.
- **Adoption (§12):** an untagged local row opens with the server key; an
  untagged `awskms` row falls through to AWS KMS; the sweep converts a local
  row and the payload is unchanged; a revoked `Cipher` opens neither.
- **Revoke ordering (Section 4):** a `Decrypt` paused after its AEAD load
  completes across a revoke; a fresh one after it returns `ErrKeyRevoked`.
- **Sweep (§11):** compare-and-swap loses to each of the five racing paths
  (new `Put`, repair reseal, incoming peer copy, delete or tombstone, reseal
  retirement); an already-current row is a no-op; the stale-rows gauge.
- **Vault correlation (E3):** the fake asserts `X-Aerol-Correlation-ID` on
  every call, and the fixed background id on boot, re-check and sweep calls.
- **Provider tags (§4):** a row wrapped by another provider returns the
  "wrapped by X; node configured for Y" error, not a bare decrypt failure.
- **Full stop (§10):** after a revoke, `clear_inspect_ca` reaches the
  gateway; the gateway drops its CA once sandboxd has been gone past the
  bound it was sent, and keeps it across a short restart; open SSH and
  exec streams close, health reports degraded, and a retired version never
  trips a revoke.
- **PKCS#11 (§2):** enterprise mode refuses a non-hardware slot; re-login
  after a reopened session; the label mapping (current missing → revoked,
  decrypt-only missing → retired, unknown → decrypt failure).
- **Security (Section 3):** `--generate` refuses on a joiner (S5); a custody
  change between boots writes `key_custody_changed` (S7); a Vault key name
  with `/` or `..` is refused (S9).
- **`sandboxd key`:** `unwrap --to-file` round-trips to the same key and
  refuses without `--i-understand-plaintext`; `wrap --generate` refuses when any key exists; env-file
  loading order; the daemon never generates in cluster mode or with an
  existing `state.db`; a joiner without the wrapped file refuses to start.

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
  - key revoked on a running node (KMS disable, Vault key deleted, HSM key
    destroyed) → within the bound, the node fails closed as Design §10 says,
    a `key_revoked` event, the alert fires; and a Vault 403 alone does
    **not** revoke;
  - key store down at boot with `wrapped` → refuses to start, and recovers
    after the key store returns;
  - restart with 50 secret-bearing sandboxes → in-flight cap respected, all
    open;
  - `sandboxd key rewrap` after rotation;
  - rotate, wait for the stale-rows gauge to reach 0 on every node, retire the
    old version, then fail over a sandbox sealed before the rotation: it
    opens (the CEO 10x promise);
  - a joiner without the wrapped file refuses to start;
  - a fresh cluster built with `cluster-init.sh` / `cluster-join.sh
    --key-custody wrapped` (through the Terraform `key_custody` variable, since
    the itest reuses the prod module), and a single node with `install.sh
    --key-custody wrapped`: no plaintext key in the key file, `cluster.env`,
    the cred bundle or the S3 bundle object;
  - backup, then restore onto a fresh node with the key store reachable;
  - switch a running 3-node `local` cluster to `vault`: fail over a sandbox
    sealed before the switch, once before the sweep converts it and once after
    (CEO-M1).

## Docs

- **New page** `key-custody.mdx` ("Use your own key store"). It is a top-level
  feature, so it gets its own page per CLAUDE.md, via `/add-docs-page`. Its
  examples are operator config, so like `cli.mdx` it ends with a "Same thing
  from the SDK" section: a five-tab create with env, showing that SDK code does
  not change.
- **Update:**
  - `cluster-secrets.mdx`: provider table (`:31-33`), steps (`:119-121`), and
    a general "startup check" section;
  - `enterprise/architecture.mdx:40`, `:138`, `:173-178`;
  - `enterprise/deployment.mdx:79`, `:87`, `:96` ("your key store", not "AWS KMS");
  - `enterprise/index.mdx:54` (rename the `Vault` node that means "sealed
    secrets") and `:75`;
  - `enterprise/hardening.mdx` HV-5 and HC-5;
  - `enterprise/security-controls.mdx` DP-5;
  - `enterprise/audit-evidence.mdx` SC-12;
  - `enterprise/responsibility.mdx:36`;
  - `engineering-secret-handling.mdx:180`, `:224`;
  - `setup/config-defaults.md:64-66`, `:96`, `:192`;
  - `setup/runbooks/secrets-and-audit.md:89`, `:768`.
- **Vault Agent example:** `key-custody.mdx` shows an Agent config for both
  auth modes (token file, API proxy). Config files are allowed; raw HTTP is
  not.
- **Rule:** name only vendors that passed Phase 6. Everything else is "any HSM
  with PKCS#11 v2.40 AES-GCM; not yet tested".

## Phases

One PR per phase, stacked, with nothing merged until the whole stack is green.

| Phase | What | Effort |
|---|---|---|
| 0 | **Spike, no product code.** On Vault and OpenBao: decrypt with the wrong AAD is rejected; `rewrap` accepts `associated_data`; the error text for a deleted key and for a retired version; audited request headers record `X-Aerol-Correlation-ID`. On SoftHSM2 and CloudHSM: GCM IV behavior and `CKF_HW_SLOT`. Choose miekg or crypto11. Measure p50, p99 and throughput for AWS KMS, Vault and CloudHSM from one region. Record the results in this file. | S (plus about 2 hours of CloudHSM) |
| 1 | **Seam split.** `secrets.NewWrapper(ctx, opts)` builds the wrapper from config with no store, and `NewProvider` takes it. Add the `limitedWrapper` decorator with its background budget, the provider tags, the `ErrKeyRevoked` and `ErrKeyVersionRetired` sentinels (and the `awskms` mapping change), the boot canary and strict-boot option for every external provider (the enterprise **requirement** lands in Phase 5), the cluster-mode key check at `config.go:2573-2580`, the reserved create slot, the provider-error to HTTP 503 mapping in `apihttp.WriteStoreAwareError` (Section 2), and the config validation. No other behavior change for `local` or `awskms`. | S |
| 2 | The `vault` wrapper and its tests, including the correlation header (CEO-E3). | M |
| 3 | The `pkcs11` wrapper, session pool and tests. | M |
| 4 | Wrapped server key: boot order in `pkg/daemon`, the revocable `Cipher`, `sandboxd key wrap [--generate]/rewrap/verify/status/unwrap` with env-file loading, `--key-custody wrapped` in `cluster-init.sh`, `cluster-join.sh`, `install.sh` and the Terraform bootstrap (`key_custody` variable, `bootstrap.sh.tftpl`) (fact 10), the joiner refusal, the backup and restore scripts, the custody gauge (CEO-E1), the revocation re-check (CEO-E2), and the full-stop pieces: `clear_inspect_ca`, closing proxied sessions, degraded health (CEO-E2R). | L |
| 4b | Rewrap sweep (CEO-E4): in-daemon sweep with compare-and-swap, the stale-rows gauge, `ErrKeyVersionRetired` handling, and local → external conversion with the untagged-row open order (CEO-M1, Design §12). | L |
| 5 | Enterprise rules, the docs page and updates, config-defaults, the runbook, the `SandboxdServerKeyPlaintext`, `SandboxdKeyRevoked`, `SandboxdKeyVersionRetiredInUse` and `SandboxdKeyStoreThrottling` alerts with runbooks and `alerts_test.go` rows (CEO-E1, CEO-E2, CEO-E4, Section 8), the key-custody Grafana row, the revoke procedure per backend, and the Vault Agent example. | S |
| 6 | The tag-gated CI job, the live itest scenarios, the CloudHSM run, and an Outcome section here. | M (AWS time) |
| 7 | **One release later (F2):** enterprise mode with an external provider refuses `custody=file`; release notes announce it one release ahead. | S |

Phase 1 also rewrites the reject at `internal/config/config.go:2599-2602` and
the comment at `pkg/secrets/factory.go:38-40`. The `vault` value keeps
refusing to boot until Phase 2 lands in the same stack.

## Decisions needed

Each open question blocks a named phase. A phase does not start until its
gates are answered and written back here.

| Question | Owner | Blocks |
|---|---|---|
| ~~F1 plaintext-present refusal~~ answered: refuse (D13) | founder | — |
| ~~F2 enterprise requires `wrapped`~~ answered: warn, then refuse (D16) | founder | — |
| ~~F3 first HSM to certify~~ answered: AWS CloudHSM (D14) | founder | — |
| E1 Vault auth modes | eng | Phase 2 |
| E2 thin Vault client | eng | Phase 2 |
| E3 key-wrap-pad fallback | eng | Phase 3 (after Phase 0) |
| E4 untagged rows: local first, then `awskms` (§12, revised by CEO-M1) | eng | Phase 1 |
| E9 narrow the rolling-switch window (§12 known limit) | eng | Phase 4b |
| E5 `limitedWrapper` defaults in config | eng | Phase 1 |
| CEO-E2a auto-recover after re-enable | eng | Phase 4 |
| CEO-E2b placement awareness | eng | Phase 4 (rule 6 if yes) |
| CEO-E2c defaults (5 min × 3) | eng | Phase 4 (after Phase 0) |
| CEO-E2e an older running egress gateway rejects `clear_inspect_ca` after an upgrade: restart it, or alert that the revoke is incomplete | eng | Phase 4 |
| E6 PKCS#11 in-process, or in a helper process (a vendor library crash or memory bug cannot take down sandboxd or read its memory) | eng | Phase 3 |
| E7 PKCS#11 code in its own package (`pkg/secrets/pkcs11`) so cgo and the vendor library stay out of the base package | eng | Phase 3 |
| E8 one short retry for `ErrProviderUnavailable` inside the caller's deadline (Vault active-node failover returns 503 for seconds) | eng | Phase 1 |
| CEO-E4a sweep cadence | eng | Phase 4b |
| CEO-E4b no cross-node sealed-byte comparison | eng | Phase 4b |
| Phase 0: Vault and OpenBao reject a wrong AAD on decrypt (else the derived-key fallback) | Phase 0 result | Phase 2 |
| Phase 0: miekg vs crypto11 | Phase 0 result | Phase 3 |
| Phase 0: CloudHSM sets `CKF_HW_SLOT` (if not, enterprise mode would refuse it; rule changes) | Phase 0 result | Phase 3 |
| Phase 0: Transit `rewrap` accepts `associated_data` (else decrypt and re-encrypt) | Phase 0 result | Phase 4b |
| Phase 0: Vault and OpenBao audited request headers record `X-Aerol-Correlation-ID` | Phase 0 result | Phase 2 (header), Phase 5 (docs) |
| Phase 0: Vault error text for a deleted key and for a retired version | Phase 0 result | Phase 2 (error table) |
| Phase 0: create-path wait under a restart storm, with the reserved slot | Phase 0 result | Phase 1 |
| Background budget (2 slots) and re-check settings (5 min × 3) | eng, with Phase 0 numbers | Phase 1 (budget), Phase 4 (re-check) |

The design text already assumes the recommended answer to F1 and F2. If the
founder answers differently, §3 and §7 change.

**Founder:**

- **F1.** With `custody=wrapped`, refuse to start while a plaintext key is
  still present? **Answered 2026-10-20 (D13): yes, refuse.**
- **F2.** Enterprise mode with an external provider: make `wrapped` required?
  **Answered 2026-10-20 (D16): warn for one release, then refuse (Phase 7).**
- **F3.** Which HSM to certify first? **Answered 2026-10-20 (D14): AWS
  CloudHSM.** Thales Luna or Entrust nShield wait for a vendor or customer dev
  partition.

**Eng review:**

- **E1.** Vault auth limited to a token file and the Agent proxy in v1?
  *Recommend yes.*
- **E2.** Thin Vault client instead of `hashicorp/vault/api`? *Recommend thin.*
- **E3.** Ship the PKCS#11 key-wrap-pad fallback? *Recommend:* only if Phase 0
  finds a target HSM without GCM.
- **E4.** Untagged rows: try the server key (local) first, then `awskms`
  (Design §12, after CEO-M1). Check that no other wrapper has produced rows in
  the field. FakeKMS is test-only.
- **E5.** Put `limitedWrapper` defaults (8 in flight, backoff ceiling) in
  config now, or hard-code them until measurements exist?

## Follow-ups (not in this plan)

- ~~**F-R1:** a rewrap sweep~~ Now in scope as Design §11 (CEO-E4).
- Live provider switching: a decrypt-only previous provider plus a reseal.
- Server key (data key) rotation: add a key ID to the `Cipher` format, then
  reseal.
- GCP Cloud KMS and Azure Key Vault: TODOS.md entry (CEO-E5); triggers are
  the K8s plan's GKE phase and a named Azure customer. KMIP: on customer
  demand.
- HSM signing of audit heads: TODOS.md entry (CEO-E6).

## CEO review (2026-10-20)

Run by `/plan-ceo-review` on branch `plans/customer-key-custody` (PR #784).
Rows marked *pending* are proposals, not accepted changes.

### Step 0 evidence

**0A. Premise.** The real problem is an enterprise security review that asks
"can we hold the keys, in our Vault or HSM, and revoke you?" The target outcome
is a true "yes" for self-hosted installs. Doing nothing costs those deals, and
the current "AWS KMS" answer is narrower than a reviewer will assume: it covers
only cluster-secret copies (fact 3). The plan attacks the pain directly, not a
proxy, because the wrapped server key (Design §3) is what makes the answer
true. Open premise: no named customer is recorded as asking. The gap row says
"Vault **or** PKCS#11", so one of the two may be enough.

**Landscape** (WebSearch; Aside not installed).
- Layer 1: Vault itself works this way. It stores its root key encrypted by
  the HSM or KMS and decrypts it at startup. That is Design §3.
- Layer 2: E2B and Daytona document no customer-held keys for sandboxes; E2B's
  BYOC leaves at-rest encryption to the customer's cloud. Google's agent
  sandbox offers Cloud KMS CMEK. Vault and HSM support would be ahead of the
  agent-sandbox field, not catching up.
- Layer 3: Vault Enterprise "managed keys" run Transit encrypt and decrypt
  inside a PKCS#11 HSM. A customer whose HSM sits behind Vault Enterprise is
  served by the `vault` provider alone. Direct PKCS#11 is only for HSM shops
  without Vault Enterprise Plus.

**0B. Reuse.** `DataKeyWrapper` + `KMSProvider` (`pkg/secrets/kms.go:16-19`,
`kms_provider.go`), `FakeKMS`, `testProviderContract`
(`provider_contract_test.go:17`), the 0400 mode check
(`wrap_key_loader.go:72`), the boot canary and strict boot
(`service.go:765-805`), the error classes and metrics
(`metrics.go:316`), and the subcommand pattern (`gatewayd/run.go:21`). Nothing
is rebuilt.

**Reality rows.**

| Premise | Claim | Receipt | Verdict |
|---|---|---|---|
| Facts 1–9 | seam, vault reject, server-key scope, plaintext key, boot order, untagged DEK, throttle unhandled, create-path Wrap, cgo build | file:line in "What the code does today" | verified (static read) |
| Vault AAD on encrypt | `associated_data` exists | Vault + OpenBao Transit API docs | verified (docs) |
| Vault AAD on decrypt | wrong AAD is rejected | none | **unverified** (Phase 0) |
| CloudHSM IV | HSM refuses caller IV | AWS CloudHSM known-issues page | verified (docs) |
| miekg/pkcs11 | loads the module with `dlopen` | none | **unverified** (in-distribution) |
| Vault Agent proxy | `use_auto_auth_token` injects the token | none | **unverified** (in-distribution) |
| Audit field cheap | "`omitempty` does not change old event hashes" | learning `auditlog-field-rollout` | **finding**: true for old events, but an older binary in a mixed cluster drops the new field and fails strict boot verify; needs gossip feature-version gating |
| Key distribution | plan says "Ansible playbook `wrap-server-key.yml`" | `scripts/cluster-init.sh:411-446`, `cluster-join.sh:374-397` | **finding**: clusters share the key through these scripts, not Ansible. They write the plaintext key into the env drop-in and into `aerolvm-cred-bundle.tar.gz`. Design §3 must cover both. |

unverified=3

```
REALITY: premise-table finding unverified=3; audit-field and key-distribution claims wrong plans/customer-key-custody.md:1068
REALITY: already-done pass no vault/pkcs11/HSM work on origin/main since 2026-09-01 pkg/secrets/factory.go:62
REALITY: surface-check finding Ansible has no install or key playbook; key ships via cluster-init.sh/cluster-join.sh scripts/cluster-init.sh:446
REALITY: binding-decisions pass no branch decisions; E5 and no-DEK-cache honored plans/secrets-hardening.md:907
REALITY: numbers pass every latency/throughput number deferred to Phase 0; 8 in-flight, 50/node, 10 s timeout are [estimated] plans/customer-key-custody.md:518
REALITY: deferred-asks pass no linked issue plans/customer-key-custody.md:7
REALITY: pr-count pass no ship-policy.json; one PR per phase, stacked, per user rule plans/customer-key-custody.md:941
```

**Retrospective.** The secrets area took nine review rounds on PR #374, and
the lesson recorded then was "recurring findings on one mechanism mean its
ownership model is wrong". The server key has the same smell: today it lives in
four places (key file, env var, cluster env drop-in, cred bundle) and the plan
named only two.

**0C. Dream state.**

```
  CURRENT STATE                 THIS PLAN                       12-MONTH IDEAL
  AWS KMS wraps cluster-        Vault + (HSM) wrap DEKs and     One customer root of trust.
  secret copies only. Server -> the server key. No decrypt  ->  Every AerolVM key (data,
  key is plaintext in 4         key on disk. Revoke = shred.    signing, node TLS) is wrapped
  places. No Vault, no HSM.     Rotation of the wrapping key.   by it or lives in it. Rewrap
                                                                sweeps, any cloud KMS, K8s.
```

### Spec review

Three adversarial reviews of this plan plus the CEO summary (cap reached):
scores 5, 6 and 6 out of 10; 21, 17 and 8 issues. Each round's fixes were not
re-raised by the next review. The 8 issues from the third review were fixed
after it and checked by the author against this text, not by a fourth
review: **issues verified: 8 of 8** (applied edits, not a verdict). Two
reviews surfaced founder choices, answered as CEO-E2R (D9) and CEO-E2D (D10).

### 0I. Timeline check

```
HOUR 1 (foundations):  the DataKeyWrapper seam; boot order (cipher before
                       store, fact 5); the one shared *Cipher; the five
                       plaintext locations (fact 10); the error classes and
                       the two new sentinels; limitedWrapper's two budgets.
HOUR 2-3 (core logic): Phase 0 answers drive the code: Vault AAD on decrypt
                       and rewrap, CloudHSM IV and CKF_HW_SLOT, Vault error
                       text. Watch an Encrypt racing Cipher.Revoke(): an
                       in-flight call must finish or fail, never half-seal.
HOUR 4-5 (integration): config.go:2573-2580; cluster-init/join, install.sh
                       and the Terraform bootstrap; the egress gateway is a
                       separate long-lived process, so after an upgrade an
                       OLD gateway may reject the new clear_inspect_ca op
                       (gate CEO-E2e); SSH gateway session close; health.
HOUR 6+ (polish/tests): an OpenBao node in the itest harness; CloudHSM cost
                       and teardown; docs naming only tested vendors; alerts
                       and runbooks for three new alerts.
```

Effort: human team about 6–8 weeks; CC + gstack about 3–5 days of build plus
AWS time for Phase 0 and Phase 6 [estimated]. No scope or feasibility blocker
needs an answer before eng review; the Phase 0 results gate their phases
(gate table).

### Review sections

#### Section 1: Architecture

```
                         customer key store
      AWS KMS   |   Vault / OpenBao Transit    |   HSM via PKCS#11
          ^                ^ TLS, or Vault Agent       ^ vendor .so, session pool
          |                | proxy on loopback         | (cgo, own package)
  +-------+----------------+---------------------------+--------------+
  | pkg/secrets  DataKeyWrapper: awskms | vault | pkcs11               |
  |   tag check (§4) -> limitedWrapper: 8 foreground (1 for creates)   |
  |                                     + 2 background                 |
  +-------+------------------------------------+-----------------------+
          | Wrap/Unwrap(DEK)                   | Unwrap(server key): boot,
          v                                    v re-check every 5 min
  KMSProvider (cluster-secret      server-key custody (wrapped file)
  copies) -> BlobStore (SQLite)        |
          ^                            v
  rewrap sweep (in daemon,       revocable *Cipher (one, shared) ---> store: toolbox
  CAS under lockSecretSandboxOps)      |                              tokens, env, ...
                                       +---> service: registry, mounts, egress CA
                                       +---> egress gateway (own unit, 0600 socket):
                                       |     set_inspect_ca / clear_inspect_ca (new)
                                       +---> SSH gateway: close sessions on revoke
  sandboxd key CLI (wrap [--generate] / rewrap / verify / status)
     reads env files + wrapped file, calls the key store, never opens state.db
```

**Data flows (four paths each).**

| Flow | Happy | Nil | Empty | Error |
|---|---|---|---|---|
| Wrap on a cluster create with secrets | one key-store call, tagged blob stored | no secrets: `Put` returns a zero handle, no call (`kms_provider.go`) | empty bag: same as nil (`Secrets.IsEmpty`) | unavailable/denied/throttled: create fails with the class; throttled retried inside the deadline |
| Boot unwrap of the server key | unwrap, `check` matches, `Cipher` built | no wrapped file: single-node + no `state.db` → generate; otherwise refuse | zero-length or malformed file → refuse with the path | unavailable → exit (systemd restarts); denied/revoked → exit with the class |
| Re-check (every 5 min) | ok, counter reset | no wrapped file (custody=file) → no re-check | n/a | unavailable/denied → canary gauge 0, counter reset; retired → stale alert; revoked → counter +1 |
| Rewrap sweep | stale row rewrapped under CAS | no stale rows → no-op | empty table → no-op | CAS lost → skip; key-store error → stop this pass, retry next cadence |

**State machine: server-key custody on one node.**

```
 [boot] --unwrap ok, check ok--> ACTIVE
 [boot] --any unwrap error-----> exit (systemd Restart=always)
 ACTIVE --re-check ok----------> ACTIVE (counter = 0)
 ACTIVE --unavailable/denied---> ACTIVE (counter = 0, canary gauge 0)
 ACTIVE --retired--------------> ACTIVE (stale alert)
 ACTIVE --revoked, n < N-------> ACTIVE (counter n+1)
 ACTIVE --revoked, n = N-------> REVOKED (Cipher.Revoke, CA cleared in both
                                          processes, sessions closed, health degraded)
 REVOKED --re-check ok, check ok--> ACTIVE  only if CEO-E2a = auto-recover
 REVOKED --restart-------------> [boot]
 Impossible: REVOKED -> ACTIVE without a fresh unwrap AND a matching check
 (the swap takes the new AEAD only from that unwrap).
```

**Coupling.** New edges: `pkg/secrets` → `pkg/auditlog` for the
correlation id (checked: `pkg/auditlog` imports nothing internal, so no cycle);
`pkg/daemon` boot order (wrapper → cipher → store); service → egress gateway
(one new op); service → SSH gateway (a revoked signal). `pkg/secrets` is linked
only into `sandboxd` (checked with `go list -deps`: `cmd/aerolvm`,
`cmd/toolboxd` and `internal/egress/gatewayd` do not import it), and
`sandboxd` is already cgo. The PKCS#11 code still goes in its own package so
the vendor library stays out of the base package (pending E7).

**Scaling.** What breaks first at 10x/100x is the key store, not sandboxd:
Vault Transit runs on one active node, an HSM partition has session and
operation limits. The limiter, the background budget and the sweep's random
start are the controls; Phase 0 measures the ceilings.

**Single points of failure.** The key store, by design: boot needs it with
`wrapped`, cluster creates with secrets need it, and failover opens need it.
Vault Agent on each node is a second, local one: if it dies, the node sees
403 or connection refused. The docs list Agent as a node dependency with
`Restart=always`.

**Security architecture.** No new HTTP endpoint. New surfaces: the
`sandboxd key` CLI (root: it reads the 0600 wrapped file and the env files),
one new op on the existing root-owned 0600 gateway socket
(`internal/egress/gatewayd/run.go:81-108`), and the sweep's row rewrite (daemon
only, CAS).

**Production failures per integration.**

| Integration | Realistic failure | Handled? |
|---|---|---|
| Vault | active-node failover returns 503 for seconds | creates with secrets fail fast as Unavailable. **Gap**: no short retry for Unavailable (pending E8) |
| HSM | HA failover drops sessions | yes: reopen + re-login (§2) |
| AWS KMS | throttling | yes: limiter backoff |
| Egress gateway | still the old binary after an upgrade | pending CEO-E2e |
| Terraform | bootstrap without the custody flag | yes: `key_custody` variable (§3) |

**Rollback posture.** Providers and custody are opt-in settings; turning a
provider off is a config change. **Gap:** once a node runs `custody=wrapped`,
there is no supported way back to `custody=file`. The plan has no command to
turn the wrapped key back into a key file. See CEO-R1.

**Value test.** `sandboxd key status` is a product surface the founder asked
for (D3); security questionnaires and operators consume it. It does not
retire.

#### Section 2: Error and rescue map

```
METHOD / CODEPATH            | WHAT CAN GO WRONG                          | CLASS
-----------------------------|--------------------------------------------|---------------------------
vault Wrap/Unwrap            | TLS or CA error; connection refused         | ErrProviderUnavailable
                             | 5xx, sealed, standby, timeout               | ErrProviderUnavailable
                             | 429                                         | ErrProviderThrottled
                             | 403 after one token-file reload             | ErrProviderDenied
                             | token file unreadable at runtime            | ErrProviderDenied (path in msg)
                             | 400 decrypt failure                         | ErrDecryptFailed
                             | 400 key not found / version retired         | ErrKeyRevoked / ErrKeyVersionRetired
                             | malformed JSON, missing field               | ErrProviderUnavailable
pkcs11 Wrap/Unwrap           | session lost, device removed                | reopen + re-login + 1 retry
                             | session count, pool wait                    | ErrProviderThrottled
                             | PIN errors                                  | ErrProviderDenied
                             | label rules (§2)                            | ErrKeyRevoked / Retired / DecryptFailed
                             | vendor library crash                        | process dies (pending E6)
limitedWrapper               | caller deadline hit while waiting for slot  | ErrProviderThrottled ("waited Nms")
server-key boot unwrap       | file missing / bad mode / bad JSON / format | refuse to start, path in message
                             | check mismatch                              | refuse: "wrong key-store key?"
                             | key store unavailable / denied / revoked    | exit with the class; systemd restarts
re-check loop                | any error                                   | classified (§10); panic recovered
revoke actions               | clear_inspect_ca fails (gateway down)       | log + alert; gateway self-drops after bound
sweep                        | CAS lost                                    | skip (counter)
                             | key-store or SQLite error                   | stop this pass, retry next cadence
sandboxd key CLI             | env file missing                            | warn, use process env
                             | wrap: wrapped file exists, same key         | no-op (idempotent)
                             | wrap: wrapped file exists, other key        | refuse
API surface (every handler)  | any provider class reaching a handler       | today: 500 (GAP, see below)

EXCEPTION CLASS          | RESCUED? | RESCUE ACTION                             | USER SEES
-------------------------|----------|-------------------------------------------|---------------------------------
ErrProviderThrottled     | Y        | jittered backoff inside the deadline      | slower call, then 503 + Retry-After
ErrProviderUnavailable   | partial  | none today (pending E8: one short retry)  | 503 "key store unavailable"
ErrProviderDenied        | N        | re-raise with context; alert via canary   | 503 "key store denied this node"
ErrKeyRevoked            | Y        | full stop (§10)                           | 503 "key revoked by the key store"
ErrKeyVersionRetired     | N        | stale alert; row unusable on this node    | 503 "key version retired"
ErrDecryptFailed         | N        | re-raise, audit event                     | 500 (data integrity; unchanged)
```

**GAP (fixed in the plan): every provider error reaches API callers as a
500.** No provider class is mapped for HTTP (`grep` of `pkg/api` finds none;
only `internal/service/metrics.go:314-318` classifies them). After a full-stop
revoke every request would read "internal error". Phase 1 maps the five
provider classes to 503 with a stable error code (`key_store_unavailable`,
`key_store_throttled` with `Retry-After`, `key_store_denied`, `key_revoked`,
`key_version_retired`) through `apihttp.WriteStoreAwareError`, which CLAUDE.md
already requires for surfaced errors. This also changes `awskms` today (500 →
503), and the Phase 1 PR calls that out.

**Rules applied.** No catch-all: each backend has its own mapping table.
Logs name the operation, sandbox id, ref, backend and class, and **never** a
request or response body, because a decrypt response carries the plaintext
DEK. The wrapped server-key file is refused if it has group or other
permission bits, with the same check as `wrap_key_loader.go:72`. Missing or
unreadable token files and PKCS#11 modules are boot errors with the path in
the message.

#### Section 3: Security and threat model

| # | Threat | Likelihood | Impact | Mitigated? |
|---|---|---|---|---|
| S1 | Wrong or hostile `SB_SECRET_VAULT_ADDR`: `Wrap` sends the DEK in plaintext to whoever answers | Low | High | Yes: TLS with `SB_SECRET_VAULT_CACERT`, plain `http://` only on loopback |
| S2 | Node root steals the Vault token or reaches the Agent proxy | Medium | Medium | Accepted limit, stated in the claim: decrypts only while the key store is reachable, every call is logged, revocable |
| S3 | PIN file stolen | Medium | Medium | Same as S2; group/other bits refused (`wrap_key_loader.go:72` check) |
| S4 | Vendor PKCS#11 library runs inside sandboxd: a crash takes the daemon down, a bug can read its memory | Low | High | Pending E6 (helper process) |
| S5 | `sandboxd key wrap --generate` run on a joiner by mistake mints a second server key and splits the cluster | Medium | High | **Fixed here:** in cluster mode `--generate` also needs `--seed`, an empty raft directory and no `state.db` |
| S6 | A plaintext key left behind after migration makes the claim false | Medium | High | F1 (asked below) |
| S7 | Custody downgrade (custody set back to `file`, by `unwrap --to-file` or by hand) goes unnoticed | Medium | Medium | **Fixed here:** the daemon records the last custody it booted with and writes a `key_custody_changed` audit event (a new `Kind`) when it differs; the custody alert (§9) fires too |
| S8 | Key material in logs | Medium | High | Fixed in Section 2: no request or response bodies, ever |
| S9 | Path tricks in config: a key name like `../../sys/x` sends the node token to another Vault path | Low | Medium | **Fixed here:** `SB_SECRET_VAULT_KEY_NAME` must match `[A-Za-z0-9_-]+`; the mount is validated as path segments with no `..` |
| S10 | Two clusters share one Transit key: a wrapped file copied from cluster A boots on cluster B with the wrong key, and B can then decrypt nothing | Low | Medium (availability, not confidentiality) | Docs: one Transit key, label or KMS key per cluster |
| S11 | Revoke used as a denial-of-service | Low | High | By design: only the key's owner can do it, and that is the feature |
| S12 | The `sandboxd key` CLI's own operations are not in the daemon's hash-chained audit log (single writer) | High | Low | The key store logs every call; the CLI logs to journald; S7 covers custody changes at the next boot |

**Dependencies.** `github.com/miekg/pkcs11` (BSD-3, used by the crypto11
family and through it by sigstore tooling). No `hashicorp/vault/api`. No new
dependency for the custody report, the re-check or the sweep.

**Input validation.** Every new setting is validated at config load with a
table test: URLs (scheme, loopback rule), paths (exist, mode), labels and key
names (character set, length), and integers (positive, upper bound).

#### Section 4: Data flow and edge cases

**Wrapped-file write** (CLI `wrap` / `rewrap`, and the sweep's own rewrap):

```
INPUT (env files, flags) -> VALIDATE (config, custody, F1 rules, S5 rules)
  -> TRANSFORM (generate or unwrap; Wrap under the current key)
  -> PERSIST (temp file 0600 in the same dir, fsync, rename, fsync dir)
  -> OUTPUT (read back: unwrap + check; print the plaintext path to delete)
shadow: disk full -> temp removed, old file untouched | crash mid-write ->
temp left, removed on next run, rename never half-applied | existing file,
same key -> no-op | existing file, other key -> refuse | key store down ->
nothing written
```

**Async ordering.**

1. **Revoke vs in-flight crypto.** Invariant: once `Cipher.Revoke()` returns,
   no new `Encrypt` or `Decrypt` succeeds. Each call loads the AEAD pointer
   once at its start. A call that loaded it before the swap may finish; one
   that loads after gets `ErrKeyRevoked`. The contract says so: "operations
   already running when the revoke lands may complete." Test: hold a
   `Decrypt` after its load, revoke, release, then start a fresh `Decrypt`;
   the first returns plaintext, the second `ErrKeyRevoked`.
2. **Sweep vs the five writers.** Invariant: the sweep never overwrites a row
   newer than the one it read, and never brings back a deleted row.

```
 sweep                         | Put / repair / peer copy / delete | row (ref, gen, bytes)
 read (g, b)                   |                                   | (g, b)
 [await key-store rewrap] -----+--> lock; write (g+1, b'); unlock  | (g+1, b')
 lock; UPDATE ... WHERE gen=g  |                                   |
   AND bytes=b -> 0 rows; skip |                                   | (g+1, b')  OK
 -- other order --
 read (g, b); rewrap; lock;    | waits for lock                    |
 UPDATE -> 1 row; unlock ------+--> lock; write (g+1, b'); unlock  | (g+1, b')  OK
 -- delete during the await --
 read (g, b); [await] ---------+--> delete row / tombstone         | (none)
 lock; UPDATE WHERE ... -> 0   |                                   | (none)     OK (never upsert)
```

   **Fix applied:** the sweep holds `lockSecretSandboxOps` only around the
   compare-and-write, never across the key-store call (the plan said "takes
   the lock per sandbox", which would block that sandbox's creates and opens
   for a full network round trip). The write is a conditional `UPDATE`, never
   an upsert. Test: pause the sweep after its read, run each racing writer to
   completion, release, and assert the row is the writer's.
3. **Two rewraps of the server-key file** (the sweep and an operator's
   `sandboxd key rewrap`). Both write atomically and both produce a valid
   wrapping of the same key, so the last rename wins safely. The re-check
   reads either the old or the new file, never a torn one.

**Interaction edge cases.**

| Interaction | Edge case | Handled? | How |
|---|---|---|---|
| `sandboxd key wrap` | run twice | yes | same key in the wrapped file → no-op |
| `sandboxd key wrap` | interrupted after the wrapped file, before the plaintext is deleted | yes | re-run is a no-op; F1 refusal keeps the node down until the plaintext is gone |
| `sandboxd key wrap --generate` | run on a joiner | yes | refused (S5) |
| Retiring a key version | done before the stale gauge reached 0 everywhere | partly | stale alert; those rows fail on that node. Runbook: lower `min_decryption_version` again, or restore the label if not yet destroyed |
| Revoke | key disabled, then re-enabled inside 15 minutes | yes | an ok re-check resets the counter, no trip |
| Revoke | key disabled for 20 minutes, then re-enabled | pending | trips; recovery per CEO-E2a |
| Restore | backup restored onto a fresh node | yes | backup includes the wrapped file; key store must be reachable |
| Upgrade | sandboxd new, egress gateway still old | pending | CEO-E2e |

#### Section 5: Code quality

- **Where the code goes** (fits existing patterns): `pkg/secrets/vault.go`,
  `limited.go`, `custody.go` (the wrapped-file format and boot decision), the
  revocable AEAD inside `secrets.go`; PKCS#11 in its own package (E7), like
  `pkg/wasm` keeps wasmtime behind a tag; the re-check and sweep as
  `internal/service/key_recheck.go` and `key_rewrap_sweep.go`; the
  `sandboxd key` subcommand dispatched from `cmd/sandboxd/main.go` like
  `egress-gateway`.
- **Reuse, not copies.** `encryptionContextAAD` moves out of `fake_kms.go`
  (already planned). The group/other permission check in
  `wrap_key_loader.go:72` becomes one helper used by the upstream wrap key, the
  PIN file and the wrapped server-key file, instead of three copies.
  `CanaryWrapUnwrap` (`kms.go`) stays the one canary.
- **Branching.** The boot custody decision has many inputs (custody setting,
  plaintext present, wrapped present, cluster mode, `state.db` present,
  seed). Write it as a pure function returning an action, tested by a table,
  and keep the side effects in a separate executor. The per-backend error
  classifiers are lookup tables, not long `switch` chains.
- **Over-engineering check.** Three limiter numbers (8 foreground, 1 reserved
  for creates, 2 background) are the most knobs in the plan; E5 decides
  whether any of them is a setting. Nothing else is speculative: every part
  traces to a decision row.
- No issues beyond these.

#### Section 6: Tests

```
NEW THING                         TYPE              HAPPY / FAILURE / EDGE
vault wrapper                     unit (httptest)   wrap+unwrap / 403,429,5xx,bad JSON / token reload, AAD mismatch
pkcs11 wrapper                    unit (fake p11)   wrap+unwrap / session loss, PIN / label rules, re-login
  real backends                   tag-gated CI      vault -dev, bao -dev, SoftHSM2 contract suite
limitedWrapper                    unit              cap / deadline while waiting / bg never takes fg slots
provider tags                     unit              same tag / other tag / untagged: local first, then awskms
wrapped server key + boot         unit + daemon     boot ok / each refusal (F1, S5, mode, check) / first-start generate
sandboxd key CLI                  unit + itest      wrap, rewrap, verify, status, unwrap / refusals / idempotent re-run
custody report + gauge            unit (table)      each config combination incl. software token
re-check + revoke (full stop)     unit + live UC    trip after N / 403 never trips, retired never trips / reset, recovery
egress gateway clear op           unit + live       cleared / gateway down / self-drop after bound
SSH session close on revoke       unit              open sessions closed / none open
sweep                             unit + live UC    rewrap / CAS loses to 5 writers / already current, rotate-then-retire
API 503 mapping                   unit              each class / Retry-After / no body in logs
cluster scripts + Terraform       live itest        wrapped cluster built / no plaintext anywhere / joiner refusal
```

**Assertion check** (requirement → observable assertion → wrong result
rejected → `no_claim`):

| Requirement | Assertion | Rejects | no_claim |
|---|---|---|---|
| No plaintext key on a wrapped node | key file, env, `cluster.env`, bundle and S3 object hold no 32-byte key (live) | any plaintext copy | none beyond protects |
| Revoke within the bound | after a KMS disable / Vault delete, the next N re-checks trip; then create, exec, files return 503 `key_revoked` | a node still serving after N intervals | real 15-minute timing (interval shortened in the itest) |
| 403 never revokes | N consecutive 403s leave the node ACTIVE | a token expiry taking a node down | Vault Agent's real token renewal (faked by deleting the token file) |
| Sweep never loses a write | each racing writer's bytes survive | an older generation written back | contention at fleet scale |
| Creates never wait on background work | a create's `Wrap` with both background slots busy completes without waiting for them | a create queued behind the sweep | create latency under real Vault load (Phase 0 measures) |

**2am Friday test:** the live revoke-and-recover UC on a 3-node cluster with
OpenBao. **Hostile QA:** a fake Vault returning truncated JSON, a wrong
`vault:vN`, and 403 on every other call. **Chaos:** partition one node from the
key store for longer than the revoke bound and check it neither trips a
revoke nor serves secrets after a restart. A live Vault active-node failover
during creates is pending with E8 (it only matters if E8 adds the retry).
**Flakiness:** every timer (re-check, gateway self-drop, sweep cadence) takes an
injectable clock and interval; live UCs shorten the intervals by config.

#### Section 7: Performance

- **Sweep reads.** The sweep pages `cluster_secrets` by primary key (as
  `migrateLegacyPlaintextSecrets` does, `internal/store/store.go:1217`) and
  parses each envelope's `WrappedKey` prefix; no full-table load, no new index
  (it reads every local row once per pass by design).
- **Memory.** Bounded by the page size; DEKs are 32 bytes and live only for
  one call. No cache (scope rule).
- **Slow paths** [estimated; Phase 0 measures]: (1) boot unwrap, one call plus
  a TLS handshake or PKCS#11 login; (2) a sweep pass after a rotation, about
  rows × call latency ÷ 2 slots, so 1,000 rows at 5 ms is about 2.5 s per
  node; (3) a restart storm's opens, capped by the limiter.
- **Connection pressure (finding, fixed here).** At the review bar, 2,000
  nodes × 10 slots is up to 20k TLS connections to one Vault active node.
  The Vault client keeps at most 2 idle connections per node with a 90 s
  idle timeout [estimated], so a quiet fleet holds about 4k, and Phase 0
  measures Vault under that load. Vault Enterprise performance standbys can
  serve Transit; the docs mention it for large fleets.
- **Background sizing.** The sweep's worst case is one pass over every local
  row; on error it stops and retries next cadence, it never retries in a
  tight loop.

#### Section 8: Observability

- **Metrics.** Reuse `aerolvm_secret_provider_canary_ok`
  (`internal/service/metrics.go:69`); the re-check now updates it too, so the
  existing `SandboxdSecretProviderCanaryFailing` alert
  (`setup/prometheus/sandboxd-alerts.yml:629`) also covers "this node can no
  longer see revocations". Extend `classifySecretMetricError`
  (`metrics.go:300`) with `key_revoked` and `key_version_retired`. New:
  `aerolvm_key_store_calls_total{backend,op,class}`,
  `aerolvm_key_store_call_seconds{backend,op}` (histogram),
  `aerolvm_key_store_limiter_wait_seconds{budget}`,
  `aerolvm_key_custody{class,custody,enterprise}`,
  `aerolvm_key_rows_stale`, `aerolvm_key_revoked`. Names follow the existing
  `aerolvm_` prefix (the plan's `sandboxd_` names are renamed to match).
- **Alerts** in `setup/prometheus/sandboxd-alerts.yml`, each with a runbook
  entry and a row in `alerts_test.go`: `SandboxdServerKeyPlaintext`,
  `SandboxdKeyRevoked` (critical), `SandboxdKeyVersionRetiredInUse`, and
  `SandboxdKeyStoreThrottling` (sustained throttled rate).
- **Logs.** One structured line for the boot custody decision; re-check
  results logged only on a change of class, not every 5 minutes; revoke,
  recover and custody-change at error level; one summary line per sweep pass.
  Never a request or response body (Section 2).
- **Tracing.** One OTEL span per key-store call (`internal/observability`) with
  backend, op and class, carrying the correlation id from E3.
- **Dashboard.** A key-custody row in the existing Grafana set under
  `setup/grafana/` (14 dashboards today): custody per node, key-store
  latency and error class by backend, limiter wait, stale rows, revoked
  nodes.
- **Three weeks later.** `key_revoked` and `key_custody_changed` audit
  events, the class metrics, and the key store's own log joined by
  correlation id reconstruct what happened.

#### Section 9: Deployment and rollout

- **Migrations.** No schema change: tags live inside wrapped-key bytes, the
  sweep rewrites existing rows, and the last-custody marker (S7) is a small
  file in the state directory.
- **Flags.** Everything is opt-in: `SB_SECRET_PROVIDER` (default `local`) and
  `SB_CREDENTIAL_KEY_CUSTODY` (default `file`).
- **Changes that reach existing deployments without any flag** (each called
  out in its PR): `awskms` error classes for a disabled or deleted key
  (Phase 1); provider errors as 503 instead of 500 (Phase 1); the limiter on
  the `awskms` create path (Phase 1).
- **Rollout order.** The stack merges as a whole. Upgrade nodes one at a
  time; with `custody=file` and the provider unchanged, a new node behaves as
  today. Turn on `wrapped` node by node afterwards: wrapped and file nodes can
  run side by side because they hold the same key.
- **Mixed versions.** Old nodes never see `vault:` or `p11:` rows, because a
  cluster runs one provider. The new `key_revoked` and `key_custody_changed`
  audit kinds are new `Kind` values, not new fields, so older binaries verify
  the chain (learning `auditlog-field-rollout`).
- **Finding: adopting a provider on an existing cluster breaks failover for
  existing sandboxes.** Most clusters run the default `local` provider. Its
  rows wrap each DEK under the server key with recipient binding
  (`pkg/secrets/envelope.go:130`, opened with a recipient check at `:229`).
  After `SB_SECRET_PROVIDER=vault`, `KMSProvider` cannot open them, so every
  sandbox sealed before the switch loses its failover copy until it is
  recreated. The plan calls live switching a non-goal but never says this is
  the normal way customers adopt it. See CEO-M1.
- **Rollback.** Provider and custody flags back to their defaults, plus
  `sandboxd key unwrap --to-file` for wrapped custody (CEO-R1).
- **Post-deploy checks.** First 5 minutes: `sandboxd key status --check` on
  each node, `aerolvm_secret_provider_canary_ok` = 1 everywhere, no
  `SandboxdServerKeyPlaintext` in enterprise. First hour: a create with
  secrets and one failover per node role.

#### Section 10: Long-term trajectory

- **Debt introduced.** Two providers to keep green on every release (vault,
  pkcs11), a cgo vendor-library path, four new alerts, a fourth source format
  in the sweep, and three limiter numbers. Operational debt: Vault Agent and
  the HSM client become node dependencies. Docs debt: per-backend revoke and
  rotation procedures that must track vendor changes.
- **Path dependency.** The provider tags and the wrapped-file `format` field
  keep later work (external → external switching, GCP/Azure, signing keys)
  free of format changes. The revocable `Cipher` is the hook a later
  data-key rotation would use.
- **Reversibility: 4/5.** Providers and custody are flags with a tested way
  back (`unwrap --to-file`, CEO-R1). The one-way doors are deliberate:
  deleting the key in the key store (crypto-shred) and retiring a version
  before the sweep finishes.
- **Ecosystem fit.** Follows the seam the secrets-hardening plan built,
  CLAUDE.md's opt-in default rule, and the existing alert, runbook and
  Grafana layout.
- **One year from now.** A new engineer finds one interface, three wrappers
  and one custody file format; this plan plus `key-custody.mdx` explain
  them.
- **What comes next.** The deferred CEO-E5 (GCP, Azure) and CEO-E6 (HSM
  signing) both reuse this plan's seam and session pool, so the cherry-picks
  chosen were the right base. None of the deferred items turned out to be
  needed by the accepted ones.

#### Section 11: Design and UX

SKIPPED (no UI scope). No dashboard screen (`pkg/api/dashboard.html`) or SDK
surface changes; the operator surfaces are a CLI, metrics and docs.

### Decision ledger

| ID and owner | Contract and evidence | Current | Proposed | Status | Exact approval and scope |
|---|---|---|---|---|---|
| CEO-1 (founder) | Which providers this stack ships. Gap row says "Vault or PKCS#11"; Vault Enterprise managed keys front an HSM for Transit (landscape, Layer 3) | `vault` + `pkcs11` + wrapped server key (Phases 0–6) | A) `vault` + wrapped key now, `pkcs11` deferred with a demand trigger; B) keep both | approved (B) | D1 answer 2026-10-20: "B) Vault + HSM now". Scope: `vault`, `pkcs11` and the wrapped server key all ship in this stack; Phases 0–6 unchanged. Against the recommendation (A). |
| CEO-F1 (plan) | Key distribution path; `scripts/cluster-init.sh:411-446`, `cluster-join.sh:380-433` | Design §3 named an Ansible playbook | Fact 10 + the four-places table in Design §3 + Phase 4 row | applied (repair) | In scope under the HOLD check "repairs needed to meet stated invariants": the plan's own claim is false without it. No scope change. |
| CEO-F2 (plan) | Audit `kek` field cost; learning `auditlog-field-rollout` | "cheap" | Design §8 text corrected; field stays deferred | applied (fact correction) | Corrects a wrong statement about a deferred item. No scope change. |
| CEO-E1 (founder) | Key custody report; Delight scan | not in plan | A) Add B) Defer C) Skip | approved (Add) | D3 answer 2026-10-20: "A) Add". Scope: Design §9, Phase 4 (`sandboxd key status`, gauge), Phase 5 (alert + runbook). |
| CEO-E2 (founder) | Revocation within minutes; The claim said "after its next restart" | not in plan | A) Add B) Defer C) Skip | approved (Add) | D4 answer 2026-10-20: "A) Add", against the Defer recommendation. Scope: Design §10, claim text, Phase 4/5/6 rows. Open implementation choices CEO-E2a/b/c go to eng review. |
| CEO-E3 (founder) | Vault audit correlation; Design §8 | not in plan | A) Add B) Defer C) Skip | approved (Add) | D5 answer 2026-10-20: "A) Add". Scope: Design §1 "Audit correlation", Phase 2 row, docs section in Phase 5. |
| CEO-E4 (founder) | Rewrap sweep F-R1; Follow-ups | follow-up | A) Add B) Defer C) Skip | approved (Add) | D6 answer 2026-10-20: "A) Add". Scope: Design §11, new Phase 4b, Design §1 rotation text, Follow-ups. Open choices CEO-E4a/b go to eng review. |
| CEO-E5 (founder) | GCP / Azure KMS; Non-goals | non-goal | A) Add B) Defer C) Skip | deferred | D7 answer 2026-10-20: "B) Defer". TODOS.md entry "GCP Cloud KMS and Azure Key Vault key providers"; Non-goals updated. |
| CEO-E6 (founder) | HSM signing of audit heads; Non-goals | non-goal | A) Add B) Defer C) Skip | deferred | D8 answer 2026-10-20: "B) Defer". TODOS.md entry "HSM signing of audit chain heads"; Non-goals updated. |
| CEO-E2R (founder) | What a revoke stops. Spec review found toolbox tokens are sealed with the server key and opened on every `Store.Get` (`internal/store/store.go:2191-2213`), so "creates with no secrets still work" was false | D4: drop keys; "creates with no secrets still work; running sandboxes keep running" | A) full stop; B) split toolbox tokens onto a separate node key; C) withdraw E2 to TODOS.md | approved (A) | D9 answer 2026-10-20: "A) Full stop". Reopened D4 on a changed fact; D4's acceptance of E2 stands, its "secrets only" wording is replaced. Scope: Design §10 "On a revoke", the claim. |
| CEO-E2D (founder) | Direct sandbox routes after a revoke. Spec review 3: `{id}.{domain}` routes go Caddy → toolboxd (`pkg/caddy/client.go:216-237`), toolboxd checks only the bearer token (`cmd/toolboxd/main.go:567-577`), and E2B hands that token to clients (`pkg/api/e2b/handlers.go:1153-1158`) | claim says "no … exec, file access" | A) narrow the claim; B) remove the node's toolbox routes on revoke; C) also stop the node's sandboxes | approved (A) | D10 answer 2026-10-20: "A) Narrow the claim". Scope: the claim and Design §10 name the direct-route exception; no route removal, no sandbox stop. |
| CEO-R1 (founder) | Rollback from `custody=wrapped` to `custody=file`; Section 1 rollback posture | no path back | A) `sandboxd key unwrap --to-file`; B) document decrypting with the key store's own CLI; C) no way back | approved (A) | D12 answer 2026-10-20: "A) Unwrap command". Scope: §3 subcommand, Phase 4 row, test row. |
| F1 (founder) | Plaintext key still present with `custody=wrapped`; "Decisions needed" F1, Section 3 S6 | recommended yes, assumed in §3 boot step 2 | A) refuse to start; B) start, warn, alert; C) delete the plaintext automatically | approved (A) | D13 answer 2026-10-20: "A) Refuse to start". Plan already matched (§3 boot step 2); no text change beyond marking F1 settled. |
| F3 (founder) | First HSM to certify; "Decisions needed" F3, Section 6 | recommended AWS CloudHSM | A) AWS CloudHSM; B) SoftHSM2 only in v1; C) a vendor HSM (Thales Luna / Entrust nShield) | approved (A) | D14 answer 2026-10-20: "A) AWS CloudHSM". Plan already matched (Testing, Phase 0/6); marked settled. |
| CEO-M1 (founder) | Adopting an external provider on an existing `local` cluster; Section 9 finding | non-goal ("live switching"), no adoption path | A) local → external migration via the sweep; B) document new clusters / recreate only; C) full live switching between any providers | approved (A) | D15 answer 2026-10-20: "A) Local → external". Scope: Design §12, Non-goals narrowed, Phase 4b (now L), tests, gate rows E4 (revised) and E9. |
| F2 (founder) | Enterprise mode with an external provider and `custody=file`; "Decisions needed" F2, §7 | recommended warn one release, then refuse | A) warn one release, then refuse; B) refuse from the first release; C) never require, alert only | approved (A) | D16 answer 2026-10-20: "A) Warn, then refuse". §7 already matched; Phase 7 added for the flip one release later. |
| CEO-A1 (founder) | HTTP status for key-store errors; Section 2 GAP (today every provider class is a 500) | applied in the plan pending approval: all five classes → 503 with stable codes, including `awskms` | A) all five classes → 503; B) only the two new classes (revoked, retired) → 503, others stay 500; C) leave all as 500 | approved (A) | D17 answer 2026-10-20: "A) All five → 503". Plan already matched (Section 2, Phase 1, tests). |
| CEO-A2 (founder) | Custody-change audit event; Section 3 S7 | applied in the plan pending approval: `key_custody_changed` event + last-custody marker | A) add the event; B) rely on the custody report and alert only | approved (A) | D18 answer 2026-10-20: "A) Add the event". Plan already matched (Section 3 S7, §3 unwrap note, tests). |

Repairs applied without their own row, each covered by an approved row:
Section 3 S5 (`--generate` guard) and S9 (name validation), the logging and
file-mode rules (Section 2), and Vault idle-connection limits (Section 7)
repair invariants of CEO-1; the sweep's lock-only-around-CAS rule (Section 4)
repairs CEO-E4's "loses every race"; the metrics, alerts, dashboard row and
tracing (Section 8) are launch scope for CEO-E1, CEO-E2 and CEO-E4; Phase 7
delivers F2 (D16). Pending eng choices (gate table) are not approvals and
stay open.

Approval readiness: PASS. Checked rows: CEO-1 (D1 → B), CEO-E1 (D3 → Add),
CEO-E2 (D4 → Add), CEO-E2R (D9 → A), CEO-E2D (D10 → A), CEO-E3 (D5 → Add),
CEO-E4 (D6 → Add), CEO-E5 (D7 → Defer), CEO-E6 (D8 → Defer), CEO-R1 (D12 → A),
F1 (D13 → A), F3 (D14 → A), CEO-M1 (D15 → A), F2 (D16 → A), CEO-A1 (D17 → A),
CEO-A2 (D18 → A); repairs CEO-F1 and CEO-F2 (HOLD check 3); documents
approved D11 → A.

### Mode

SELECTIVE EXPANSION, from the D2 answer (2026-10-20) against a SCOPE
REDUCTION recommendation. CEO-1 governs: `vault`, `pkcs11` and the wrapped
server key all ship.

### Hold-scope checks

1. **Complexity.** About 40 changed files [estimated] and five new parts
   before the cherry-picks (seven after CEO-E2 and CEO-E4 added the re-check
   and the sweep): the Vault client, the PKCS#11 session pool,
   `limitedWrapper`, server-key custody, and the `sandboxd key` subcommand. Each maps to a stated
   requirement, and merging any two loses one. No cut proposed. One overlap is
   left for eng review: the SoftHSM2 live scenario repeats the tag-gated CI
   job, and a CloudHSM **cluster** scenario would prove more.
2. **Deferrable without breaking the claim** (as of before the cherry-picks;
   CEO-E4 later made retirement a supported flow): only `sandboxd key rewrap`.
   Transit versions, KMS rotation and `SB_SECRET_PKCS11_DECRYPT_KEY_LABELS`
   all keep old keys decrypting, so retiring an old key can wait. It is S
   effort and pairs with the rotation docs, so no deferral is proposed.
3. **Invariants kept:** `local` contacts nothing; single-node and local mode
   unchanged; no new key-store calls on `CreateSandbox`; E5 stays out. Repair
   applied: CEO-F1.

### 10x check

The 10x version is "AerolVM never holds a key you cannot see or take back".
A security reviewer gets a custody report generated by the node itself,
revocation takes effect across the fleet in minutes rather than at the next
restart, and every unwrap made for a request joins to a sandboxd audit event
(background calls carry a fixed, recognisable id). The plan already builds the hard part (the wrapping); the 10x pieces
are mostly small surfaces on top of it.

### Delight scan

- `sandboxd key status`: one table of every key class and where it lives.
- A custody metric and alert, so a node left on a plaintext key shows on a
  dashboard.
- A correlation header on Vault calls, so Vault's audit log joins to ours the
  way CloudTrail already shows the KMS encryption context.
- A "revoke AerolVM" runbook with the exact behavior of running nodes.
- A Vault Agent config example in `packaging/`, next to the systemd unit.

**Platform potential:** the same seam takes GCP Cloud KMS and Azure Key Vault
(the K8s plan's GKE Marketplace phase would want Cloud KMS), and the PKCS#11
session pool is the base for HSM signing of audit heads.

### Cherry-pick candidates (each asked separately)

| Row | Candidate | Effort | Risk |
|---|---|---|---|
| CEO-E1 | Key custody report: `sandboxd key status`, a custody metric, an enterprise alert | S | low |
| CEO-E2 | Revocation within minutes: a runtime key re-check that drops the in-memory server key on a deliberate revoke signal (never a 403) | M | medium |
| CEO-E3 | Vault audit correlation header, plus docs for Vault's audited headers | S | low |
| CEO-E4 | Rewrap sweep (F-R1), so old key versions can be retired | M | medium |
| CEO-E5 | GCP Cloud KMS and Azure Key Vault wrappers | M (code), L (test accounts) | low–medium |
| CEO-E6 | HSM signing of audit chain heads, on the PKCS#11 pool | L | medium–high |

The packaging example folds into the docs work, so it is not a separate row.

### Answered: CEO-1 (D1 → B, Vault + HSM now)

Commitment comparison:

```text
Commitment              | Source/approval  | Current                | A                                              | B
vault provider          | Design §1        | in                     | in                                             | in
pkcs11 provider         | Design §2        | in                     | deferred to TODOS.md; trigger = a named        | in
                        |                  |                        | customer whose HSM is not behind Vault Ent.    |
wrapped server key      | Design §3        | in                     | in                                             | in
provider tags           | Design §4        | vault: + p11:          | vault: now; p11: reserved                      | vault: + p11:
limitedWrapper          | Design §5        | in                     | in                                             | in
new cgo dependency      | fact 9           | miekg/pkcs11           | none                                           | miekg/pkcs11
SoftHSM2 CI + CloudHSM  | Testing          | in                     | moves with pkcs11                              | in
HSM claim in docs       | The claim        | Vault/OpenBao or HSM   | "an HSM behind Vault Enterprise managed keys   | "or an HSM via PKCS#11"
                        |                  |                        | (HashiCorp feature; not tested by us)"         |
effort                  | Phases           | L                      | M                                              | L
```

Question: D1 — CEO-1: Ship the direct HSM (PKCS#11) provider in this stack, or Vault first and HSM on demand?
Project: plans/customer-key-custody on PR #784, the plan for customer-held keys.
ELI10: The ask was "Vault or HSM". Vault is a key server many companies already run, and Vault Enterprise can keep its keys inside an HSM, so a Vault-only build already reaches some HSM customers. Talking to an HSM directly is the harder half: C library loading, vendor quirks, session limits, and a paid CloudHSM test run.
Stakes if we pick wrong: build HSM now with no buyer and we carry vendor C-library code nobody uses; skip it and a bank with an HSM but no Vault Enterprise hits a wall.
Recommendation: A because no named deal needs a direct HSM yet, and Vault plus the wrapped server key makes the claim true for most buyers at about half the risk. Pick B if a deal in hand has an HSM and no Vault Enterprise.
Note: options differ in kind, not coverage — no completeness score.
Header: HSM scope
A) Vault first, HSM on demand (recommended)
Ship vault and the wrapped server key; defer pkcs11 to TODOS.md until a named customer's HSM is not behind Vault Enterprise. Effort M, risk low, same seam; verified by Vault/OpenBao dev CI and the live itest. ✅ Half the provider code, no new C dependency, and no CloudHSM bill this quarter. ✅ HSM shops on Vault Enterprise are covered on day one through its managed keys. ❌ An HSM shop without Vault Enterprise Plus gets "not yet", and that tier is expensive for them to buy.
B) Vault + HSM now
Ship both providers and the wrapped server key in one stack. Effort L, risk medium (cgo, vendor quirks), same seam; verified by SoftHSM2 CI and one CloudHSM run. ✅ Answers "HSM" directly for any vendor with PKCS#11, with or without Vault. ✅ Docs can name tested HSMs (SoftHSM2, CloudHSM) instead of pointing at HashiCorp's feature. ❌ Doubles the provider work and adds a vendor C-library path we must support on every release.

### Answered: CEO-E1 (D3 → Add)

### Answered: CEO-E2 (D4 → Add)

### Answered: CEO-E3 (D5 → Add)

### Answered: CEO-E4 (D6 → Add)

### Answered: CEO-E5 (D7 → Defer)

### Answered: CEO-E6 (D8 → Defer)

Commitment comparison:

```text
Commitment                   | Source/approval              | Current    | A (Add)                                   | B (Defer)                    | C (Skip)
HSM-signed audit chain heads | secrets-hardening.md:1014;   | non-goal   | heads signed by a PKCS#11 key the daemon  | TODOS.md entry, own plan;    | NOT in scope
                             | open-audit-witness Non-goals |            | cannot read; verifier checks signatures   | reuses Phase 3 session pool  |
witness / verifier format    | open-audit-witness.md        | unsigned   | new signed-head format + dual-read        | unchanged                    | unchanged
                             |                              | heads      | verifier                                  |                              |
CEO-1, CEO-E1..E5            | D1, D3-D7                    | approved   | unchanged                                 | unchanged                    | unchanged
```

Question: D8 — CEO-E6: Add HSM signing of audit chain heads to this stack?
Project: plans/customer-key-custody on PR #784; the key-custody scope is settled except this last add-on.
ELI10: The audit log's fingerprints already go to a write-once S3 bucket. A stronger version signs each fingerprint with an HSM key the server itself cannot read, so even a fully taken-over server cannot forge a believable new fingerprint. The HSM session code from this plan would make that easier, but it changes the witness format and the offline verifier, which shipped last week.
Stakes if we pick wrong: add it here and a key-custody stack also rewrites a just-shipped audit format; defer and forged-head detection stays at today's level a while longer.
Recommendation: B because it changes a different system (the audit witness and verifier) and deserves its own plan, and it gets cheaper once this plan's HSM session code exists.
Note: options differ in kind, not coverage — no completeness score.
Header: HSM signing
A) Add
Sign each witnessed chain head with a PKCS#11 key and teach `aerolvm audit verify` to check signatures, with a dual-read for old unsigned heads. Effort L, risk high (changes a shipped evidence format); reuses the Phase 3 session pool. ✅ A compromised server can no longer forge a new head that passes the verifier. ✅ Closes the second follow-up from the secrets-hardening plan in one go. ❌ Puts a format change to last week's audit witness inside an unrelated stack.
B) Defer (recommended)
Add a TODOS.md entry pointing at its own plan, to start after this plan's Phase 3 lands. Effort S (zero implementation work now), risk low. ✅ Keeps this stack about key custody and the witness format stable. ✅ Gets the HSM session code for free once Phase 3 merges. ❌ Forged-head detection stays at today's level until that plan runs.
C) Skip
Leave it out with no TODO; the existing follow-up line in the secrets-hardening plan stays the only record. Effort S (zero implementation work), risk low. ✅ No new tracking item. ✅ Nothing changes in the audit system. ❌ The follow-up keeps living only as one line in a long, finished plan.

### Answered: CEO-E2R (D9 → A, full stop)

Commitment comparison:

```text
Commitment                    | Source/approval | Current (D4)                 | A (full stop)                        | B (secrets only)                     | C (withdraw)
what fails after a revoke     | Design §10      | secret seals/opens only      | every op that reads sealed data:     | env, registry, mounts, cluster       | nothing until
                              |                 | (wrong: toolbox tokens too)  | create, exec, files, sessions;       | secrets; exec/files/sessions keep    | restart
                              |                 |                              | inspected egress (CA dropped)        | working                              |
running sandboxes             | Design §10      | keep running                 | keep running, cannot be managed      | keep running and managed             | unchanged
health                        | new             | n/a                          | Service.Health reports degraded      | unchanged                            | unchanged
toolbox-token key             | fact 3          | server key                   | server key                           | new node key (plaintext on disk) +   | server key
                              |                 |                              |                                      | column migration                     |
the claim                     | The claim       | revoke within ~15 min        | "this node stops processing your     | "your secrets go dark; AerolVM's own | "revoke at next
                              |                 |                              | data within ~15 min"                 | agent credentials stay usable"       | restart"
effort / risk                 | Phases          | M / medium                   | M / medium                           | L / medium-high                      | S / low
CEO-1, E1, E3, E4             | D1, D3, D5, D6  | approved                     | unchanged                            | unchanged                            | unchanged
```

Question: D9 — CEO-E2R (reopened D4): After a revoke, should the node stop everything, or only customer secrets?
Project: plans/customer-key-custody on PR #784; the spec reviewer found a fact that changes what you approved in D4.
ELI10: In D4 you approved fast revocation, described as "creates without secrets still work and running sandboxes keep running". That turns out to be wrong. The server key also locks each sandbox's toolbox token, the password sandboxd uses to talk to the agent inside every sandbox, and it is read on almost every request. So once the key is dropped, the node can no longer create, exec into or manage any sandbox, with or without secrets. Running sandboxes keep running, but nobody can reach them through that node.
Stakes if we pick wrong: keep the old wording and the docs promise behavior the code cannot deliver; split the keys and we bring back a plaintext key on disk, which undoes the plan's main point.
Recommendation: A because a customer who revokes means "stop processing our data", full stop is honest and simple, and B would put a plaintext key back on disk.
Note: options differ in kind, not coverage — no completeness score.
Header: Revoke effect
A) Full stop (recommended)
A revoke drops the server key, the DEKs and the in-memory egress CA. The node fails every operation that reads sealed data and reports degraded health. Effort M, risk medium; same mechanism as D4 plus a health signal; verified by the revoke UC. ✅ The promise is simple and true: this node stops processing your data. ✅ No new key and no data migration. ❌ Running sandboxes on that node can no longer be managed until the key comes back or they are recreated elsewhere.
B) Secrets only
Move toolbox tokens onto a separate node key outside customer custody, so a revoke blocks only customer secrets and the node keeps managing sandboxes. Effort L, risk medium-high (column migration). ✅ Operators keep exec and files access to running sandboxes after a revoke. ✅ A revoke has a smaller blast radius. ❌ Puts a plaintext node key back on disk, so the "no key on disk" claim gets an exception.
C) Withdraw fast revoke
Move E2 to TODOS.md with this finding; a revoke takes effect at the next restart, as before D4. Effort S (zero implementation work now), risk low. ✅ No self-lockout path in this stack. ✅ The follow-up starts with a correct picture of what the key protects. ❌ Gives back the stated ~15 minute revoke bound you chose in D4.

### Answered: CEO-E2D (D10 → A, narrow the claim)

Commitment comparison:

```text
Commitment                         | Source/approval | Current               | A (narrow claim)                  | B (remove routes)                 | C (stop sandboxes)
AerolVM API + SSH after revoke     | D9              | stopped               | stopped                           | stopped                           | stopped
direct {id}.{domain} toolbox route | spec review 3   | keeps working (claim  | keeps working; claim names it     | sandboxd deletes the node's       | gone with the sandbox
                                   |                 | says it stops: false) |                                   | toolbox routes (Caddy writes)     |
running sandboxes                  | D9              | keep running          | keep running                      | keep running, unreachable         | stopped (not destroyed)
caddy + store multi-step write     | CLAUDE.md r4    | none                  | none                              | new: rollback rule needed         | new: stop + route cleanup
effort / risk                      |                 |                       | S / low                           | M / medium                        | M / high
CEO-1, E1, E2R, E3, E4             | D1, D3, D5, D6, D9 | approved           | unchanged                         | unchanged                         | unchanged
```

Question: D10 — CEO-E2D: After a revoke, should a sandbox's own direct route keep working?
Project: plans/customer-key-custody on PR #784; the last spec review found a path the D9 full stop does not cover.
ELI10: Some clients (the E2B SDK, for one) are handed a token that lets them talk straight to the agent inside their sandbox through its public address, without going through sandboxd. A revoke stops sandboxd, but that direct path never asks sandboxd for anything, so exec and file access through it keep working until the sandbox stops. AerolVM decrypts nothing on that path: it is the customer's own token reaching the customer's own running workload.
Stakes if we pick wrong: keep the current wording and the docs promise a cutoff that does not happen; go too far and a revoke kills customer workloads, which is hard to undo.
Recommendation: A because nothing on that path uses the customer's key, the claim stays true by naming the exception, and B and C add Caddy writes or workload stops on a node that is already failing.
Note: options differ in kind, not coverage — no completeness score.
Header: Direct routes
A) Narrow the claim (recommended)
The claim says a revoke stops everything AerolVM does with your stored data (API, SSH, decrypting), and names the exception: a running sandbox's own public route keeps working for whoever holds its token, until the sandbox stops. Effort S, risk low; docs and claim text only. ✅ True, simple, and needs no new write path on a failing node. ✅ Customers keep reaching their own running workloads, which is usually what they want. ❌ A reviewer may want "revoke" to mean "nothing reachable", and must read the exception.
B) Remove the routes
On revoke, sandboxd deletes the Caddy toolbox routes for its sandboxes, and puts them back on recovery. Effort M, risk medium; needs a rollback rule under CLAUDE.md rule 4. ✅ Nothing about the sandbox is reachable through AerolVM after a revoke. ✅ No workload is stopped. ❌ Adds Caddy writes on a degraded node, and a failed delete leaves the route up anyway.
C) Stop the sandboxes
On revoke, also stop (not destroy) every sandbox on the node, which also ends its routes. Effort M, risk high. ✅ The strongest kill switch: workloads halt within the bound. ✅ Covers every path at once, including ones not found yet. ❌ A revoke now halts customer workloads, and restarting them needs the key back.

### Answered: CEO-R1 (D12 → A, unwrap command)

Commitment comparison:

```text
Commitment                      | Source/approval | Current     | A (unwrap command)                     | B (key store's own tool)          | C (none)
path back to custody=file       | Section 1       | none        | sandboxd key unwrap --to-file: writes  | runbook: decrypt the wrapped blob | none; wrapped is one-way
                                |                 |             | the key file 0600, refuses unless      | with vault/aws/pkcs11-tool,       |
                                |                 |             | --i-understand-plaintext, logs loudly  | write the key file by hand        |
plaintext on disk after rollback| The claim       | n/a         | yes, by the operator's choice          | yes, by the operator's choice     | never
works for pkcs11                | Design §2       | n/a         | yes (uses our p11: format)             | hard: our p11: format is ours     | n/a
CEO-1, E1-E4, E2R, E2D          | D1, D3-D6, D9-10| approved    | unchanged                              | unchanged                         | unchanged
```

Question: D12 — CEO-R1: How does an operator go back from a wrapped server key to a plain key file if they need to?
Project: plans/customer-key-custody on PR #784; Section 1 (architecture) found no rollback path for the wrapped key.
ELI10: Turning on "wrapped" is easy, but nothing in the plan turns it off again. If the key store causes trouble, or a customer leaves Vault, an operator needs the plain key file back, and without a command they would have to decode our wrapped file format by hand. A command makes that safe and loud; leaving it out makes wrapped a one-way door.
Stakes if we pick wrong: no way back means a key-store problem can only be fixed by fixing the key store, with nodes unable to start in the meantime.
Recommendation: A because every new setting needs a rollback path (plan partial deploys and rollbacks), and our own PKCS#11 format is impractical to decode by hand.
Note: options differ in kind, not coverage — no completeness score.
Header: Rollback path
A) Unwrap command (recommended)
Add `sandboxd key unwrap --to-file`: unwraps through the key store, writes the key file at mode 0600, refuses without an explicit acknowledgement flag, and prints a warning that the claim no longer holds. Effort S, risk low; reuses the `sandboxd key` plumbing; verified by a round-trip test. ✅ Wrapped custody becomes a two-way door with a tested way back. ✅ Works for every backend, including our own PKCS#11 format. ❌ A root user with key-store access can produce a plaintext key on purpose (they already can, with more effort).
B) Use the key store's tool
Document how to decrypt the wrapped blob with `vault`, `aws kms` or `pkcs11-tool` and write the key file by hand. Effort S (docs only), risk medium (manual steps). ✅ No command in sandboxd that writes a plaintext key. ✅ Nothing new to maintain in code. ❌ Error-prone under pressure, and for PKCS#11 the operator must parse our `p11:` format by hand.
C) No way back
Wrapped custody is permanent once turned on. Effort S (zero implementation work), risk medium. ✅ The claim can never be undone by a command. ✅ Smallest surface. ❌ A key-store outage or a migration off Vault has no recovery path except fixing the key store.

### Answered: F1 (D13 → A, refuse to start)

Commitment comparison:

```text
Commitment                         | Source/approval     | Current (assumed) | A (refuse)                 | B (warn + alert)               | C (auto-delete)
node with custody=wrapped AND a    | §3 boot step 2      | refuses           | refuses, names the file    | starts; custody report says    | starts after deleting it
plaintext key file or env var      |                     |                   | or env var                 | "plaintext present"; alert     | (no secure delete on SSD/COW)
claim holds on that node           | The claim           | yes               | yes                        | no, until cleaned up           | probably; copies may remain
migration friction                 | §3 runbook          | one extra step    | one extra step             | none                           | none
CEO-1, E1-E4, E2R, E2D, R1         | D1, D3-D6, D9, D10, D12 | approved      | unchanged                  | unchanged                      | unchanged
```

Question: D13 — F1: When a node is set to "wrapped" but a plaintext key is still on disk or in its environment, should it refuse to start?
Project: plans/customer-key-custody on PR #784; Section 3 (security) reached founder decision F1.
ELI10: After migrating, the old plaintext key file (or a forgotten line in cluster.env) may still be lying around. If the node starts anyway, a stolen disk still decrypts everything, so the "no key on disk" promise is quietly false for that node. Refusing to start forces the cleanup; warning lets the node run and nags.
Stakes if we pick wrong: warn-only lets a node look compliant while it is not; refuse-only adds one step to every migration and can surprise an operator.
Recommendation: A because the claim is the whole point of the feature, and a refusal that names the exact file is the only way to know every node really is clean.
Note: options differ in kind, not coverage — no completeness score.
Header: Plaintext left
A) Refuse to start (recommended)
The node refuses to boot and names the plaintext file or env var to remove. Effort S, risk low; already assumed in §3; verified by a boot test. ✅ A node that runs with "wrapped" is guaranteed to hold no plaintext key copy. ✅ Catches a forgotten `cluster.env` line at the first restart. ❌ Every migration needs the cleanup step before the restart, or the node stays down.
B) Warn and alert
The node starts; the custody report shows "plaintext present" and the plaintext alert fires. Effort S, risk medium. ✅ No migration can take a node down. ✅ Still visible on dashboards. ❌ The claim is false on that node until someone acts on the alert.
C) Delete it automatically
The node deletes the plaintext file on boot, then starts. Effort S, risk medium. ✅ No operator step at all. ✅ Works for the key file. ❌ Deleting a file does not erase it on SSD or copy-on-write disks, and env vars and bundle copies stay, so the claim would look true without being true.

### Answered: F3 (D14 → A, AWS CloudHSM)

Commitment comparison:

```text
Commitment                 | Source/approval | Current (recommended) | A (CloudHSM)                     | B (SoftHSM2 only)                 | C (vendor HSM)
first real HSM tested      | Testing, Phase 6| CloudHSM              | AWS CloudHSM, one cluster run    | none; software token only         | Thales Luna or Entrust nShield
docs may name              | Docs rule       | SoftHSM2 (test), CHSM | "tested with AWS CloudHSM"       | "any PKCS#11 HSM; not yet tested  | "tested with <vendor>"
                           |                 |                       |                                  | on hardware"                      |
cost / access              | Phase 0, 6      | ~hours of CloudHSM    | hourly HSM bill, AWS account we  | free                              | needs a vendor or customer dev
                           |                 |                       | already have                     |                                   | partition we do not have
enterprise mode on it      | §2 (HW slot)    | allowed if HW flag    | allowed if CKF_HW_SLOT (Phase 0) | refused (software token)          | allowed
CEO-1 (both providers)     | D1              | approved              | unchanged                        | unchanged                         | unchanged
```

Question: D14 — F3: Which real HSM do we test against first, so the docs can name it?
Project: plans/customer-key-custody on PR #784; Section 6 (tests) reached founder decision F3.
ELI10: The docs may only name hardware we have actually tested. AWS CloudHSM runs in the AWS account our test harness already uses, costs a few dollars an hour, and has a known quirk (it insists on choosing its own encryption IV) that we want to prove. Bank-style HSMs from Thales or Entrust need a partition from the vendor or a customer, which we do not have yet.
Stakes if we pick wrong: no hardware test means enterprise HSM buyers see "untested"; waiting for a vendor partition can stall the whole Phase 6.
Recommendation: A because it is the only real HSM we can reach today, it exercises the trickiest vendor quirk, and enterprise customers on AWS use it.
Note: options differ in kind, not coverage — no completeness score.
Header: First HSM
A) AWS CloudHSM (recommended)
One operator-gated cluster run on CloudHSM in Phase 6, torn down the same day; the docs name CloudHSM. Effort M (AWS time), risk low. ✅ A real network HSM, in an account and region we already use. ✅ Proves the HSM-chosen IV and session limits. ❌ An hourly bill and CloudHSM's slow cluster setup on each run.
B) SoftHSM2 only for v1
Ship with SoftHSM2 tests only; the docs say "any PKCS#11 HSM, not yet tested on hardware". Effort S, risk medium. ✅ No HSM bill and no setup time. ✅ Phase 6 is faster. ❌ HSM buyers see "untested on hardware", which weakens the D1 choice to ship the HSM provider now.
C) A vendor HSM first
Get a Thales Luna or Entrust nShield dev partition and certify on it before CloudHSM. Effort L, risk high (access we do not have). ✅ Matches what banks most often run. ✅ A stronger name for on-prem buyers. ❌ Phase 6 waits on a vendor or customer we have not lined up.

### Answered: CEO-M1 (D15 → A, local → external)

Commitment comparison:

```text
Commitment                        | Source/approval | Current              | A (local → external)                  | B (docs only)                     | C (any → any)
existing local rows after switch  | Section 9       | unopenable           | opened with the server key until the  | unopenable; recreate sandboxes    | opened via a decrypt-only
                                  |                 |                      | sweep moves them to the new provider  |                                   | previous provider
failover for old sandboxes        | secrets plan    | broken until recreate| works throughout                      | broken until recreate             | works throughout
awskms -> vault / pkcs11          | Non-goals       | unsupported          | still unsupported                     | unsupported                       | supported (both configured)
new code                          |                 | none                 | sweep handles a 4th source format +   | runbook                           | previous-provider config, second
                                  |                 |                      | trial open with the server key        |                                   | wrapper, sweep across providers
effort / risk                     |                 |                      | M / medium                            | S / low                           | L / medium-high
CEO-1, E1-E4, E2R, E2D, R1, F1, F3| prior answers   | approved             | unchanged                             | unchanged                         | unchanged
```

Question: D15 — CEO-M1: How does an existing cluster start using Vault or an HSM without breaking failover for sandboxes it already runs?
Project: plans/customer-key-custody on PR #784; Section 9 (deployment) found the adoption path missing.
ELI10: Almost every cluster today uses the default "local" mode, where each backup copy of a sandbox's secrets is locked with the server key. If the operator switches to Vault, the new code only knows how to open Vault-locked copies, so every sandbox created before the switch silently loses its ability to fail over until someone recreates it. The rewrap sweep we already approved could convert those old copies to Vault in the background, since the node still holds the server key.
Stakes if we pick wrong: docs-only means the first real customer adopting Vault breaks failover for their whole running fleet; full any-to-any switching doubles the provider setup for a rare case.
Recommendation: A because it reuses the approved sweep, covers the common path (local to Vault or HSM), and keeps failover working throughout the switch.
Note: options differ in kind, not coverage — no completeness score.
Header: Adoption path
A) Local → external (recommended)
Until the sweep converts them, the node opens old local rows with the server key (trial open, authenticated by GCM); the sweep moves each one onto the new provider. AWS KMS to Vault stays unsupported. Effort M, risk medium (one more source format in the sweep); verified by a live switch UC with failover before and after. ✅ Existing clusters adopt Vault or an HSM with no sandbox losing failover. ✅ Reuses the approved sweep and its compare-and-swap. ❌ The sweep and open path gain one more format, in the area that needed nine review rounds before.
B) Docs only
Say "adopt on a new cluster, or recreate every sandbox with secrets after switching". Effort S, risk low. ✅ No new code over sealed rows. ✅ Honest and simple to describe. ❌ Nearly every existing customer would hit broken failover or a full recreate.
C) Any provider to any
Add a decrypt-only "previous provider" setting so any switch works, including AWS KMS to Vault, and the sweep converts across providers. Effort L, risk medium-high. ✅ Covers every migration, not only from local. ✅ The Non-goal disappears. ❌ Two providers configured at once, plus the permissions for both, for a switch few customers make.

### Answered: F2 (D16 → A, warn then refuse)

Commitment comparison:

```text
Commitment                           | Source/approval | Current (assumed) | A (warn, then refuse)        | B (refuse now)                 | C (alert only)
enterprise + external + custody=file | §7              | warn, then refuse | release N: boots, warning +  | refuses to boot from release N | boots; alert fires for good
                                     |                 |                   | alert; N+1: refuses          |                                |
existing enterprise awskms installs  | §7              | upgrade safely    | upgrade safely, one release  | upgrade fails until they wrap  | never forced
                                     |                 |                   | to migrate                   |                                |
enterprise claim                     | The claim       | true from N+1     | true from N+1                | true from N                    | may be false on some nodes
CEO-1, E1-E4, E2R, E2D, R1, M1, F1, F3 | prior answers | approved          | unchanged                    | unchanged                      | unchanged
```

Question: D16 — F2: Should enterprise mode require the wrapped server key when an external key store is configured?
Project: plans/customer-key-custody on PR #784; Section 9 (rollout) reached founder decision F2.
ELI10: Enterprise mode is the setting that refuses to start unless the install meets our hardened bar. Today an enterprise install can use AWS KMS while still keeping the plain server key file, which is exactly the gap this plan closes. Requiring "wrapped" right away would break those installs the moment they upgrade; warning first gives them one release to migrate.
Stakes if we pick wrong: refuse now breaks every existing enterprise AWS KMS install on upgrade; never requiring leaves "enterprise" meaning less than buyers will assume.
Recommendation: A because it keeps upgrades safe while giving the enterprise label a firm date when it starts meaning "your key store holds the keys".
Note: options differ in kind, not coverage — no completeness score.
Header: Enterprise rule
A) Warn, then refuse (recommended)
In the release that ships this stack, enterprise mode with an external provider and a plain key file boots with a warning and the plaintext alert; one release later it refuses. Effort S, risk low. ✅ No existing enterprise install breaks on upgrade. ✅ The enterprise claim becomes strict on a stated release. ❌ For one release, "enterprise" still allows a plain key file.
B) Refuse from the first release
Enterprise mode refuses to start with an external provider and a plain key file as soon as this ships. Effort S, risk medium. ✅ The enterprise claim is strict immediately. ✅ Nothing to remember to flip later. ❌ Existing enterprise AWS KMS installs fail to start on upgrade until they run `sandboxd key wrap`.
C) Alert only, never required
Enterprise mode keeps allowing a plain key file; the custody alert is the only signal. Effort S, risk low. ✅ No install is ever forced to change. ✅ Simplest rule. ❌ "Enterprise" never guarantees key custody, which buyers will assume it does.

### Answered: CEO-A1 (D17 → A, all five → 503)

Commitment comparison:

```text
Commitment                    | Source/approval  | Current (pending) | A (all five → 503)          | B (new classes only)          | C (leave 500)
ErrKeyRevoked / Retired       | D9 (full stop)   | 503 + code        | 503 + code                  | 503 + code                    | 500 "internal error"
Unavailable/Throttled/Denied  | Section 2 GAP    | 503 + code        | 503 + code (+Retry-After)   | 500 as today                  | 500 as today
existing awskms installs      | Section 9        | 500 -> 503        | 500 -> 503 (PR call-out)    | unchanged                     | unchanged
CEO-1 .. F2                   | prior answers    | approved          | unchanged                   | unchanged                     | unchanged
```

Question: D17 — CEO-A1: When the key store fails, what HTTP status should API callers get?
Project: plans/customer-key-custody on PR #784; approval readiness found a fix applied without its own approval.
ELI10: Today, if the key store is down, throttling, or denies the node, the API answers "500 internal error", which tells a client nothing and looks like our bug. After a full-stop revoke, every request would get that. The fix returns "503 service unavailable" with a clear code such as key_revoked or key_store_throttled, so clients and SDKs can tell "try later" from "something broke". It also changes what existing AWS KMS installs return today.
Stakes if we pick wrong: leave 500s and a revoke looks like a crash to every customer; change all of them and any client that special-cases 500 sees a new status.
Recommendation: A because a revoke or outage must be visible to the caller as what it is (zero silent failures), and one consistent rule beats two.
Note: options differ in kind, not coverage — no completeness score.
Header: Error status
A) All five → 503 (recommended)
Map unavailable, throttled (with Retry-After), denied, revoked and retired to 503 with stable codes through `apihttp.WriteStoreAwareError`. Effort S, risk low; called out in the Phase 1 PR because it changes `awskms` responses. ✅ Every key-store problem tells the caller exactly what happened. ✅ SDK retry logic can act on Retry-After and the codes. ❌ Existing AWS KMS installs see 503 where they saw 500.
B) New classes only
Only revoked and retired get 503; the existing three stay 500 as today. Effort S, risk low. ✅ No change for existing AWS KMS installs. ✅ The full stop is still clear to callers. ❌ Two rules for the same kind of failure, and outages still read as internal errors.
C) Leave all as 500
No mapping. Effort S (zero implementation work), risk medium. ✅ Nothing changes for any client. ✅ Smallest diff. ❌ After a revoke, every request looks like an AerolVM bug.

### Answered: CEO-A2 (D18 → A, add the event)

Commitment comparison:

```text
Commitment                     | Source/approval | Current (pending)          | A (add the event)                    | B (report + alert only)
custody change between boots   | Section 3 S7    | key_custody_changed event  | event in the hash-chained audit log  | no event; custody report and
                               |                 | + last-custody marker file | + marker file in the state directory | gauge show the current state
enterprise visibility          | CEO-E1          | alert fires                | alert fires + audit evidence         | alert fires
non-enterprise visibility      | CEO-E1          | gauge only                 | gauge + audit evidence               | gauge only
audit chain compatibility      | auditlog rule   | new Kind value, no new field | safe for older binaries            | n/a
CEO-1 .. F2, CEO-A1            | prior answers   | approved                   | unchanged                            | unchanged
```

Question: D18 — CEO-A2: Should a change in how a node holds its key (wrapped → plain file, or back) leave a record in the audit log?
Project: plans/customer-key-custody on PR #784; approval readiness found a second fix applied without its own approval.
ELI10: An operator can turn a wrapped key back into a plain file (D12 approved that command), or flip the setting by hand. The custody report and the dashboard alert show the node's current state, but nothing records that it changed or when. This adds one audit event at the next boot that says "custody changed from wrapped to file", so an auditor sees the downgrade in the same tamper-evident log as every secret read.
Stakes if we pick wrong: without it, a node can quietly drop back to a plain key file and later return to wrapped, and no evidence shows it ever happened.
Recommendation: A because a downgrade of key custody is exactly the kind of change an auditor asks to see, and it costs one small marker file and one event.
Note: options differ in kind, not coverage — no completeness score.
Header: Custody record
A) Add the event (recommended)
At boot, the daemon compares the custody it booted with last time (a small marker file) and writes `key_custody_changed` when it differs. Effort S, risk low; a new `Kind` value, safe for older binaries; verified by a boot test. ✅ Every custody downgrade and upgrade is in the tamper-evident audit log. ✅ Works outside enterprise mode, where no alert fires. ❌ One more marker file in the state directory to keep correct.
B) Report and alert only
Rely on `sandboxd key status`, the custody gauge and the enterprise alert. Effort S (zero implementation work), risk low. ✅ No new file or event. ✅ The current state is still visible. ❌ A change that was undone before anyone looked leaves no trace.

### CEO review outputs

`PLAN_REALITY: phase=ceo rows=7/7 missing=none unverified=3 verdict=complete`

#### NOT in scope

Deferred (also in TODOS.md):

- **GCP Cloud KMS and Azure Key Vault** (CEO-E5, D7 → Defer): no GCP or Azure
  customer, and the harness is AWS-only. Triggers: the K8s plan's GKE phase;
  a named Azure customer.
- **HSM signing of audit chain heads** (CEO-E6, D8 → Defer): it changes the
  just-shipped witness format; it gets its own plan after Phase 3.

Rejected: none. No cherry-pick was skipped.

Plan non-goals that stay out:

- customer secret storage (E5 of the secrets plan);
- node TLS keys and the cluster CA in an HSM;
- shared tokens and credentials;
- rotating the server key itself;
- external → external provider switching;
- KMIP;
- a DEK cache.

#### What already exists

| Need | Existing code | Reused? |
|---|---|---|
| Key-store interface | `DataKeyWrapper`, `KMSProvider` (`pkg/secrets/kms.go:16-19`, `kms_provider.go`) | yes, unchanged |
| Contract tests | `testProviderContract` (`provider_contract_test.go:17`) | yes, for each new wrapper |
| Boot canary, strict boot | `CanaryWrapUnwrap`, `ConfigureSecretProvider` (`service.go:765`) | yes, generalised |
| Error classes, metric labels | `pkg/secrets/errors.go`, `classifySecretMetricError` (`metrics.go:300`) | yes, two classes added |
| Secret-file mode check | `wrap_key_loader.go:72` | yes, made a shared helper |
| Per-sandbox secret lock | `lockSecretSandboxOps` (`seal_distribute.go:78`) | yes, for the sweep |
| Canary gauge and alert | `aerolvm_secret_provider_canary_ok`, `SandboxdSecretProviderCanaryFailing` | yes, now also fed by the re-check |
| Subcommand pattern | `egress-gateway` (`cmd/sandboxd/main.go:79`) | yes, for `sandboxd key` |
| Thin REST client style | `pkg/caddy/client.go` | yes, for Vault |

#### Dream state delta

The plan reaches most of the 12-month ideal for data keys:

- the customer's key store holds the root;
- no decryption key sits on disk;
- revoke takes minutes;
- rotate-and-retire is safe;
- custody is visible on every node;
- existing clusters can migrate.

Still short of the ideal:

- signing keys and node TLS keys (CEO-E6 and non-goals);
- GCP and Azure (CEO-E5);
- external → external switching;
- rotating the data key itself.

#### Error and rescue registry

See Section 2. It has about 30 codepath rows. GAP 1 (provider errors reached
callers as 500) is fixed by CEO-A1. GAP 2 (no short retry for Vault
active-node failover) is pending E8.

#### Failure modes registry

```
CODEPATH                 | FAILURE MODE                         | RESCUED? | TEST? | USER SEES?                 | LOGGED?
-------------------------|--------------------------------------|----------|-------|----------------------------|--------
boot unwrap              | key store down                       | Y (exit) | Y     | node down, canary alert    | Y
boot unwrap              | plaintext still present (F1)         | Y        | Y     | refuses, names the file    | Y
boot unwrap              | wrong key (check mismatch)           | Y        | Y     | refuses                    | Y
cluster create Wrap      | key store unavailable                | partial  | Y     | 503 key_store_unavailable  | Y   (E8 retry pending)
cluster create Wrap      | throttled                            | Y        | Y     | slower, or 503 + Retry-After | Y
failover open            | stale/retired version                | N        | Y     | 503 key_version_retired + alert | Y
re-check                 | revoke signal x N                    | Y        | Y     | full stop, 503 key_revoked | Y
re-check                 | Vault 403 (token expired)            | Y        | Y     | canary alert; no revoke    | Y
revoke                   | egress gateway down                  | Y        | Y     | gateway self-drops after bound | Y
revoke                   | OLD egress gateway ignores clear op  | N        | N     | SILENT: CA stays in old gateway | N   <- CRITICAL GAP (pending CEO-E2e)
revoke                   | direct {id}.{domain} route           | by design| Y     | route keeps working (named exception, D10) | n/a
sweep                    | CAS lost                             | Y        | Y     | nothing (correct)          | Y
sweep                    | key store errors                     | Y        | Y     | stale gauge stays > 0      | Y
pkcs11                   | vendor library crash                 | N        | N     | daemon restarts            | Y   (pending E6)
pkcs11                   | HSM HA failover                      | Y        | Y     | nothing                    | Y
local -> external switch | rolling-switch window                | partial  | Y     | failover copy unusable on unswitched node | Y (E9)
```

One CRITICAL GAP, owned by eng review: CEO-E2e (an old egress gateway after
an upgrade keeps the CA key through a revoke). It blocks Phase 4.

#### Scope expansion decisions

From the CEO plan
`~/.gstack/projects/aerol-ai-microvm/ceo-plans/2026-10-20-customer-key-custody.md`:

- **Accepted:**
  - CEO-E1 (custody report);
  - CEO-E2 (revocation within minutes), refined by CEO-E2R (full stop) and
    CEO-E2D (named exception);
  - CEO-E3 (Vault audit correlation);
  - CEO-E4 (rewrap sweep);
  - from the review sections: CEO-R1 (unwrap command), CEO-M1 (local →
    external migration), CEO-A1 (503 mapping), CEO-A2 (custody-change event).
- **Deferred:** CEO-E5 and CEO-E6 (TODOS.md).
- **Skipped:** none.

#### Diagrams

Seven diagrams in this review:

1. system architecture (Section 1);
2. data-flow table (Section 1) and the wrapped-file write (Section 4);
3. custody state machine (Section 1);
4. error flow (Section 2);
5. async schedules (Section 4);
6. deployment sequence (below);
7. rollback flowchart (below).

```
DEPLOYMENT SEQUENCE
 merge whole stack -> release N -> upgrade nodes one by one (custody=file, provider unchanged: no change)
   -> set provider (local -> vault/pkcs11) on all nodes' config -> quick rolling restart (E9 window)
   -> sweep converts local rows (watch aerolvm_key_rows_stale -> 0 on every member)
   -> sandboxd key wrap on one node -> copy wrapped file -> remove plaintext (F1) -> restart node by node
   -> enterprise: release N warns on custody=file; release N+1 refuses (Phase 7)

ROLLBACK FLOWCHART
 problem after enabling wrapped custody?
   |-- key store reachable --> sandboxd key unwrap --to-file --i-understand-plaintext
   |                           -> SB_CREDENTIAL_KEY_CUSTODY=file -> restart
   |                           -> key_custody_changed event + plaintext alert
   |-- key store unreachable --> node cannot boot; restore key-store access
   |                             (no way around it by design; backups need the key store too)
 problem after switching provider?
   |-- rows already converted --> stay on the new provider (external -> local is unsupported)
   '-- rows not yet converted --> set provider back to local; unconverted local rows still open
```

#### Stale diagram audit

| Diagram | Still accurate? |
|---|---|
| `docs/.../enterprise/architecture.mdx:173` "AWS KMS, optional" | No: add Vault and HSM in Phase 5 |
| `docs/.../enterprise/deployment.mdx:79` "monitoring and AWS KMS" | No: say "your key store" in Phase 5 (added to the Docs list) |
| `docs/.../enterprise/architecture.mdx:40` "monitoring and KMS" | Partly: generalise in Phase 5 |
| `docs/.../enterprise/index.mdx:54` node labelled `Vault` meaning "sealed secrets" | Confusing once a Vault provider exists: rename the node in Phase 5 |
| `setup/arch.md:366` "ca.key remains with offline signer/HSM" | Yes |

## Implementation Tasks

Synthesized from this review's findings. Each task derives from a specific
finding above. Effort ratios assumed: tests ~50x, features ~30x,
architecture ~5x, research ~3x.

- [ ] **T1 (P1, human: ~2d / CC: ~4h)** — Phase 0 — run the spike and record the results.
  - Surfaced by: gate table, 0I.
  - Covers: Vault/OpenBao AAD on decrypt and rewrap; error texts; audited
    headers; CloudHSM IV and `CKF_HW_SLOT`; miekg vs crypto11; latency and
    create wait under a restart storm.
  - Files: `plans/customer-key-custody.md`.
  - Verify: every Phase 0 gate row has an answer.
- [ ] **T2 (P1, human: ~3d / CC: ~2h)** — Phase 1 — seam split and
  `limitedWrapper`.
  - Surfaced by: facts 5, 7; Sections 2, 7, 9.
  - Covers: budgets; tags; the `ErrKeyRevoked` and `ErrKeyVersionRetired`
    sentinels; the `awskms` mapping; the 503 mapping (CEO-A1); the
    cluster-mode key check; validation.
  - Files: `pkg/secrets/{factory,kms,limited,errors,awskms}.go`,
    `internal/config/config.go`, `pkg/api/apihttp/classify.go`.
  - Verify: `go test ./pkg/secrets/... ./internal/config/... ./pkg/api/apihttp/...`
    at ≥85% coverage.
- [ ] **T3 (P1, human: ~1w / CC: ~3h)** — Phase 2 — `vault` wrapper.
  - Surfaced by: Design §1; Sections 2, 3 (S1, S9), 7.
  - Covers: token file and Agent proxy; correlation header; idle-connection
    limits.
  - Files: `pkg/secrets/vault.go` and tests.
  - Verify: httptest suite, plus the tag-gated `vault -dev` and `bao -dev`
    contract run.
- [ ] **T4 (P1, human: ~1w / CC: ~4h)** — Phase 3 — `pkcs11` wrapper.
  - Surfaced by: Design §2; Section 3 (S4).
  - Covers: session pool; re-login; label rules; hardware-slot rule. Decide
    E6 and E7 first.
  - Files: `pkg/secrets/pkcs11/` (per E7).
  - Verify: fake `p11API` suite, plus SoftHSM2 in CI.
- [ ] **T5 (P1, human: ~2w / CC: ~1d)** — Phase 4 — wrapped server key and
  revoke.
  - Surfaced by: Design §3, §9, §10; Sections 1, 3, 4.
  - Covers: boot decision as a pure function; revocable `Cipher`;
    `sandboxd key` (including `unwrap`, CEO-R1); custody marker and event
    (CEO-A2); re-check; full stop (`clear_inspect_ca`, session close,
    degraded health); scripts and Terraform. Decide CEO-E2a, E2b and E2e
    first.
  - Files: `pkg/daemon/daemon.go`, `pkg/secrets/{secrets,custody}.go`,
    `cmd/sandboxd/main.go`, `internal/service/key_recheck.go`,
    `internal/egress/proto.go`, `internal/egress/gatewayd/daemon.go`,
    `pkg/sshgateway/gateway.go`, `scripts/cluster-{init,join}.sh`,
    `scripts/install.sh`, `scripts/sandboxd-{backup,restore}.sh`,
    `Terraform/templates/bootstrap.sh.tftpl`.
  - Verify: unit tests above, plus the live revoke-and-recover UC.
- [ ] **T6 (P1, human: ~1w / CC: ~4h)** — Phase 4b — rewrap sweep and local
  → external conversion.
  - Surfaced by: Design §11, §12; Section 4.
  - Covers: CAS, never holding the lock across the call, the stale gauge.
    Decide CEO-E4a, E4b and E9 first.
  - Files: `internal/service/key_rewrap_sweep.go`.
  - Verify: race tests against the five writers, plus the live switch UC.
- [ ] **T7 (P1, human: ~3d / CC: ~3h)** — Phase 5 — docs, alerts and
  dashboard.
  - Surfaced by: Docs; Sections 8 and 10 (stale diagrams).
  - Covers: `key-custody.mdx` plus updates; four alerts with runbooks and
    `alerts_test.go` rows; Grafana row; enterprise warn rule.
  - Files: `docs/src/content/docs/**`, `setup/prometheus/sandboxd-alerts.yml`,
    `setup/grafana/`, `setup/runbooks/secrets-and-audit.md`,
    `setup/config-defaults.md`.
  - Verify: `make docs-build` with npm 10; `go test ./setup/prometheus/...`.
- [ ] **T8 (P1, human: ~3d / CC: ~4h plus AWS time)** — Phase 6 — tag-gated
  CI job, live itests, CloudHSM run (F3), and an Outcome section here.
  - Surfaced by: Testing; Section 6.
  - Files: `.github/workflows/test.yml`, `integration-tests/suite/`.
  - Verify: `make integration-*` scenarios green, teardown clean.
- [ ] **T9 (P2, human: ~1h / CC: ~10min)** — Phase 7 — the enterprise flip
  one release later (F2).
  - Files: `internal/config/config.go`.
  - Verify: config table test.

The JSONL for `/autoplan` is written to the gstack project directory (path
in the Completion Summary).

#### Completion Summary

```
  +====================================================================+
  |            MEGA PLAN REVIEW — COMPLETION SUMMARY                   |
  +====================================================================+
  | Mode selected        | SELECTIVE EXPANSION                         |
  | System Audit         | server key plaintext in 5 places; provider  |
  |                      | errors reach callers as 500; toolbox tokens |
  |                      | sealed by the server key; local clusters    |
  |                      | had no adoption path                        |
  | Step 0               | CEO-1 both providers (D1); E1-E4 accepted,  |
  |                      | E5/E6 deferred; repairs F1/F2               |
  | Section 1  (Arch)    | 4 issues found                              |
  | Section 2  (Errors)  | ~30 error paths mapped, 2 GAPS (1 fixed)    |
  | Section 3  (Security)| 12 issues found, 6 High severity            |
  | Section 4  (Data/UX) | 8 edge cases mapped, 2 unhandled (pending)  |
  | Section 5  (Quality) | 3 issues found                              |
  | Section 6  (Tests)   | Diagram produced, 1 gap (pending E8)        |
  | Section 7  (Perf)    | 1 issue found                               |
  | Section 8  (Observ)  | 5 gaps found (all addressed)                |
  | Section 9  (Deploy)  | 4 risks flagged                             |
  | Section 10 (Future)  | Reversibility: 4/5, debt items: 6           |
  | Section 11 (Design)  | SKIPPED (no UI scope)                       |
  +--------------------------------------------------------------------+
  | NOT in scope         | written (9 items)                           |
  | What already exists  | written                                     |
  | Dream state delta    | written                                     |
  | Error/rescue registry| ~30 rows, 0 CRITICAL GAPS                   |
  | Failure modes        | 16 total, 1 CRITICAL GAP (CEO-E2e, pending) |
  | TODOS.md updates     | 2 items proposed (both added)               |
  | Scope proposals      | 6 proposed, 4 accepted (EXP + SEL)          |
  | CEO plan             | written                                     |
  | Outside voice        | codex: unavailable (MODEL_UNUSABLE); native |
  |                      | fallback: no report within 5 min            |
  | Lake Score           | N/A (no coverage-scored questions)          |
  | Diagrams produced    | 7 (arch, data flow, state, error, async,    |
  |                      | deploy, rollback)                           |
  | Stale diagrams found | 4                                           |
  | Unresolved decisions | 15 (eng-owned, gate table)                  |
  | Reality rows         | 7/7 rows (PLAN_REALITY), 3 unverified       |
  +====================================================================+
```

Tasks JSONL: `~/.gstack/projects/aerol-ai-microvm/tasks-ceo-review-20261021-161803.jsonl` (9 tasks).

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | ISSUES OPEN | 6 proposals, 4 accepted, 2 deferred; plus 4 scope decisions from the review sections (CEO-R1, CEO-M1, CEO-A1, CEO-A2) and 2 reopened refinements (CEO-E2R, CEO-E2D); 1 critical gap pending (CEO-E2e) |
| Outside Review | codex, from `/plan-ceo-review` | Independent 2nd opinion | 1 | unavailable | codex MODEL_UNUSABLE (CLI cannot decode the models response); native fallback gave no report within five minutes; no completed external review |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 0 | — | — |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — (no UI scope) |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** codex, plan-review phase, unavailable (MODEL_UNUSABLE; fix: upgrade the Codex CLI). The native Claude fallback timed out at five minutes and earns no coverage credit. Three in-host spec reviews ran inside the CEO review (scores 5, 6, 6; cap reached; last 8 fixes verified by the author).
- **VERDICT:** no review is CLEAR yet. The CEO review is complete with its founder decisions settled (D1–D18); the remaining choices are eng-owned. Eng review required.

**UNRESOLVED DECISIONS:**
- E1 Vault auth limited to a token file and the Agent proxy (blocks Phase 2)
- E2 thin Vault client instead of `hashicorp/vault/api` (blocks Phase 2)
- E3 PKCS#11 key-wrap-pad fallback, only if Phase 0 finds a no-GCM HSM (blocks Phase 3)
- E4 untagged rows: local first, then `awskms` (revised by CEO-M1; blocks Phase 1)
- E5 limiter numbers in config or hard-coded (blocks Phase 1)
- E6 PKCS#11 in-process or in a helper process (blocks Phase 3)
- E7 PKCS#11 in its own package (blocks Phase 3)
- E8 one short retry for `ErrProviderUnavailable` (blocks Phase 1)
- E9 narrowing the rolling-switch window (blocks Phase 4b)
- CEO-E2a auto-recover after the key is re-enabled, or restart only (blocks Phase 4)
- CEO-E2b revoked node tells placement to stop sending it creates (blocks Phase 4; CLAUDE.md rule 6 if yes)
- CEO-E2c re-check defaults, 5 minutes × 3 (blocks Phase 4)
- CEO-E2e an old egress gateway ignores `clear_inspect_ca` after an upgrade: the one CRITICAL GAP (blocks Phase 4)
- CEO-E4a sweep cadence and trigger (blocks Phase 4b)
- CEO-E4b confirm nothing compares sealed bytes across nodes (blocks Phase 4b)
