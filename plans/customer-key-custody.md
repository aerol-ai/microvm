# Customer key custody: HashiCorp Vault and PKCS#11 (HSM) key providers

Status: **DRAFT, reviewed.** CEO review 2026-10-20 (SELECTIVE EXPANSION, D1–D18)
and eng review 2026-10-21 to 2026-10-30 (eng D2–D26), both folded into the sections above;
records at the end. Every design decision is answered; what remains are
Phase 0 measurements, listed in "Decisions needed" with the phase each one
gates. Nothing here is built.

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

- **Copies made before a migration.** `sandboxd key wrap` wraps the **same**
  server key. Backups taken before the migration archived `/etc/sandboxd`
  (`scripts/sandboxd-backup.sh:69`), including the plaintext key in
  `cluster.env`, and old cred bundles and S3 bundle object versions hold it
  too. For a migrated install the claim holds only after those copies are
  destroyed **or** after a server-key rotation (Design §13, eng D26) retires
  the plaintext-era key; the docs give the checklist, and `sandboxd key status` shows
  "migrated from plaintext" until `sandboxd key ack-migration` (eng D24,
  outside voice OV5). A fresh wrapped install has no such copies.

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
- ~~**Rotating the server key itself.**~~ Now in scope as Design §13 (eng
  D26).
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

**Least privilege, checked (Phase 0).** With a token that may `create` on
`<mount>/encrypt/<key>`, Transit silently recreates a deleted key on the next
encrypt, which would hide a revoke. At boot sandboxd calls
`sys/capabilities-self` for its encrypt, decrypt and keys paths and refuses to
start if the encrypt path allows `create`, `sudo` or `root`. With the plan's
`update`-only policy, an encrypt against a deleted key returns 403 and the key
stays deleted.

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
Transit's `rewrap` endpoint cannot be used: it takes no `associated_data`,
and vault issue #29532 reports it fails for AAD-bound ciphertext (eng review
finding 2). The sweep decrypts and re-encrypts inside sandboxd, as an open
does.

### 2. The `pkcs11` provider (HSMs)

**Process (eng D5).** The vendor library never loads into the daemon. sandboxd
starts `sandboxd --pkcs11-helper` (the same binary, like `--wasm-worker`,
`cmd/sandboxd/main.go:39`) and talks to it over a 0600 Unix socket in
`/run/sandboxd` with four ops: Wrap, Unwrap, Ping and Info (slot flags and
labels, for the custody report and the hardware-slot rule). The session pool,
login and `C_Initialize` live in the helper. If the helper exits, sandboxd
restarts it with backoff and calls in that window return
`ErrProviderUnavailable`. Every op also carries a 5 s deadline (a constant);
if one passes it, sandboxd kills and replaces the helper, which frees any
vendor session stuck in a C call, and the `key_custody` loop runs each step
under its own deadline so it never stalls behind the helper (eng D25, outside
voice OV6). A vendor crash therefore costs a helper restart,
not the daemon, and vendor code never sees sandboxd's memory. The helper is a
child of sandboxd, so it never runs a different version. The short-lived
`sandboxd key` CLI loads the same package in its own process; a crash there
only ends the command.

**Library.** Use `github.com/miekg/pkcs11` (v1.1.2: the module graph already
pins it through containerd, and requiring Phase 0's v1.1.1 would downgrade
containerd). It loads the vendor module with
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
  into `CK_GCM_PARAMS.pIv`. SoftHSM2 accepts the caller's IV and, given a
  zeroed buffer, encrypts with that all-zero IV instead of writing one (Phase
  0). So `SB_SECRET_PKCS11_GCM_IV=auto|hsm|caller` defaults to `auto`: at helper
  start, one probe encrypt with a zeroed IV buffer decides the mode (buffer
  filled → `hsm`; buffer left zero → `caller`, with a fresh `crypto/rand` IV per
  wrap). The probe runs on a throwaway session key (`CKA_TOKEN=false`), never
  the real one (Phase 3): on a token that leaves the buffer zero it does
  encrypt with the all-zero IV, and doing that with the real key at every
  helper start would repeat a (key, IV) pair. A token that refuses session
  keys makes `auto` fail with a message to set `hsm` or `caller`. In every
  mode, a wrap whose IV comes back all zero is refused, so a nonce can never
  repeat, and an unwrap of a row with an all-zero IV is refused too.
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
| `CKR_KEY_FUNCTION_NOT_PERMITTED` (decrypt turned off), or the **current** label (`SB_SECRET_PKCS11_KEY_LABEL`) not found **while the session is logged in** (`C_GetSessionInfo` reports a user-functions state; private objects are invisible otherwise, Phase 0) | `ErrKeyRevoked` (new, Design §10) |
| a label not found while the session is **not** logged in | re-login, then search again; never a revoke on its own |
| `CKR_OBJECT_HANDLE_INVALID` on a cached key handle | search the label again, then classify |
| `CKR_PIN_INCORRECT`, `CKR_PIN_EXPIRED`, `CKR_PIN_LOCKED` | `ErrProviderDenied` |
| a label in `SB_SECRET_PKCS11_DECRYPT_KEY_LABELS` not found, while the current label still exists | `ErrKeyVersionRetired` |
| a decrypt-only label not found **and** the current label not found | `ErrKeyRevoked` (so a revoke during a rotation window still trips) |
| a `p11:` header naming a label in neither setting | `ErrDecryptFailed` ("wrapped under an unknown key label") |
| `CKR_ENCRYPTED_DATA_INVALID`, `CKR_ENCRYPTED_DATA_LEN_RANGE`, a bad `p11:` header, or `CKR_GENERAL_ERROR` from `C_Decrypt` after a successful `C_DecryptInit` (SoftHSM2 reports a GCM tag mismatch this way, Phase 0) | `ErrDecryptFailed` |
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
| `SB_SECRET_PKCS11_GCM_IV` | `auto` (default; probed at helper start), `hsm` or `caller` |

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
| `vault` | `update` on `<mount>/encrypt/<key>` and `<mount>/decrypt/<key>`; `read` on `<mount>/keys/<key>` (latest version for the sweep). No `rewrap` (eng finding 2). **Never `create`** on the encrypt path: Transit would recreate a deleted key on the next encrypt (Phase 0); sandboxd checks this at boot through `sys/capabilities-self`, so the token also needs `update` on `sys/capabilities-self` (part of Vault's `default` policy; a token made with `no_default_policy` must be granted it). |
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

*Correction (2026-10-31, live UC-301):* the unit `install.sh` writes also
sets `StartLimitBurst=10` in 5 minutes, so systemd stops restarting after
about 50 s of failed boots and the node stayed down after the key store came
back. `sandboxd-healthcheck.timer` now resets and starts a **failed** unit
every 30 s (an operator's `systemctl stop` leaves it inactive, not failed,
and it stays stopped). Still no retry loop in the daemon.

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
- `sandboxd key status`: the custody report (Design §9). After a migration
  it shows "migrated from plaintext: destroy old backups and bundles" until
  the operator runs `sandboxd key ack-migration` (eng D24).
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

**Backups.** `scripts/sandboxd-backup.sh` copies `state.db`, the raft
directory **and `/etc/sandboxd`** (`:69`), which holds the plaintext key line in
`cluster.env`. With `custody=wrapped` the script stops archiving the
plaintext key line and the key file, and adds the wrapped file; the restore
script (`scripts/sandboxd-restore.sh`) installs it (eng D24). The restore needs the key store reachable,
which the runbook states. After a key version is retired (Design §11), an
older backup's wrapped file no longer opens, so the runbook says to take a
fresh backup after every retirement.

### 4. Tag wrapped DEKs now

Vault ciphertext already starts with `vault:v`. PKCS#11 output starts with
`p11:`, as defined above. Untagged bytes are either a `local` row (DEK wrapped
under the server key) or an `awskms` row (opaque KMS blob). An untagged row is
opened with the server key first, then with AWS KMS whenever the node has
AWS KMS settings, whatever its sealing provider (Design §12, eng D22). `Unwrap` checks the tag before calling out, and a
tagged row opens with whichever configured backend its tag names, even when
that is not the sealing provider (eng D8). On a mismatch it returns `ErrProviderUnavailable` with
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
  with jittered backoff inside the caller's context deadline, and retries
  `ErrProviderUnavailable` once, for foreground calls only, after 100-300 ms of
  jitter when the deadline leaves room (eng D17). Background calls never
  retry; their next tick does. All three
  providers get it, `awskms` included. This fixes fact 7.
- **Fleet math** at the review bar (2,000 nodes, 100k sandboxes):
  - A rolling restart opens about 50 secret-bearing sandboxes per node. That is
    about 100k unwraps spread over the roll.
  - A simultaneous cold start is capped at 2,000 × 8 = 16k foreground calls in
    flight (20k with background slots).
  - Phase 0 measures what one Vault active node and one CloudHSM partition can
    sustain. The docs publish the sizing rule from that measurement, not from
    vendor claims.
- **Settings (eng D13).** Only `SB_SECRET_PROVIDER_MAX_INFLIGHT` (default 8)
  is a setting, so operators can fit it to their HSM's session limit; the
  reserved create slot, the background budget and the backoff ceiling are
  commented constants until Phase 0 gives a reason to change them.
- **Background work never blocks a create.** The re-check (Design §10) and
  the sweep (Design §11) use a separate, smaller budget (2 slots [estimated])
  inside `limitedWrapper`, so a create's `Wrap` never waits behind them. The
  PKCS#11 session pool is sized foreground plus background (8 + 2), so the
  cold-start bound in the fleet math above becomes 2,000 × 10 = 20k calls in flight.
- **Sweep load after a rotation.** Every copy on every node is rewrapped, and
  on Vault every call lands on one active node. The sweep runs at boot and
  hourly (eng D19), starts after a random delay of up to an hour, and runs
  only on the 2 background slots, which caps it at 2 × 2,000 = 4k in flight
  fleet-wide [estimated]. An idle pass is a local scan plus, on Vault, one key
  version read (about 0.6 calls/s at 2,000 nodes [estimated]).
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
`SB_SECRET_PROVIDER_RECHECK_INTERVAL` (default 5 minutes, eng D18, with
jitter), each node **unwraps its stored wrapped server key again** and
compares the `check` value. This uses real data, not a fresh canary, so it
also catches a retired version still in use (reported as stale, not as a
revoke). It runs on the background budget (Design §5). Cost:
one key-store call per node per interval, about 7 calls per second across
2,000 nodes [estimated].

**Only deliberate signals count as a revoke.** Phase 1 adds an
`ErrKeyRevoked` sentinel (and `ErrKeyVersionRetired` for stale versions) to
`pkg/secrets/errors.go`, and `openRawEnvelope` passes both through like the
three existing provider classes (`pkg/secrets/envelope.go:257`; outside voice
OV7). Each re-check result is sorted into ok, unavailable,
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
results (default 3, so about 15 minutes, eng D18), the node:

- **stops processing the customer's data (full stop, CEO-E2R).** It calls
  `Cipher.Revoke()`, drops its in-memory egress-inspection CA
  (`egress.InspectCA`, loaded at `internal/service/egress_inspect.go:117`),
  and stops opening cluster-secret copies. The egress gateway's
  `clear_inspect_ca` drops the CA, drops every sandbox's injection secrets
  (`Spec.Secrets`, read by inject rules at `internal/egress/proxy/inspect.go:251`)
  and closes established inspected connections, which otherwise keep the
  inspector they loaded at connect time (`:108-110`); inject rules then deny
  with `ReasonSecretMissing`, and sandboxd's Syncs carry no secrets while the
  node is revoked (eng D21, outside voice OV2). The CA key also lives in the
  **egress gateway**, a separate process with its own systemd unit
  (`packaging/aerolvm-egress-gateway.service`), which gets it through
  `set_inspect_ca` (`internal/egress/proto.go:38`,
  `internal/egress/gatewayd/daemon.go:151`) and has no way to clear it. Phase 4
  adds a `clear_inspect_ca` op that sandboxd sends on revoke. The gateway also
  drops the CA once sandboxd has been gone longer than the revoke bound
  (about 15 minutes; sandboxd sends the bound in the `set_inspect_ca`
  message, so the gateway needs no setting of its own), so a sandboxd that can no longer boot cannot leave the
  key behind, while an ordinary sandboxd restart (seconds) does not break
  inspected egress. An **older** gateway still running after an upgrade
  answers `unknown op` (`internal/egress/server.go:278`); sandboxd then
  restarts `aerolvm-egress-gateway.service`, the gateway comes back without
  the CA (it is memory-only), and a revoked sandboxd never resends it. The
  alert and audit event say the gateway was restarted (eng D4); Go cannot promise memory is
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

- ~~**CEO-E2a.**~~ Answered (eng D12): auto-recover. On the first re-check
  after a revoke where the stored key unwraps and its check matches, the loop
  swaps the AEAD back into the shared `Cipher`, re-sends the CA and the
  sandboxes' injection secrets to the gateway (`set_inspect_ca` and the next
  Sync), returns health to ok, resets the counter and writes a
  `key_recovered` audit event (a new `Kind`). A later revoke needs N revoked
  results again.
- ~~**CEO-E2b.**~~ Answered (eng D7): no placement change. A revoke is
  cluster-wide because every node wraps the same server key; failing closed
  with 503 `key_revoked` is enough, and `internal/cluster` is untouched.
- ~~**CEO-E2c.**~~ Answered (eng D18): defaults 5 minutes × 3 (about 15
  minutes), both settings. The exact Vault error text stays a Phase 0 item.

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
| `vault` | `vault:vN:` prefix with N below the latest version | decrypt and re-encrypt in sandboxd (Transit `rewrap` takes no AAD; eng finding 2) |
| `pkcs11` | label in the `p11:` header is not `SB_SECRET_PKCS11_KEY_LABEL` | decrypt under the old label, encrypt under the new, inside one session |

AWS KMS has no sweep: it rotates key material in place and never retires it,
and a changed key id is a provider switch, which v1 does not support.

**Where it runs.** Inside the daemon, never in a second process: SQLite has
one writer per process (`MaxOpenConns=1`), and a CLI opening the database
alongside the daemon would break that. It runs at boot and then on a cadence
every hour after that (eng D19, a constant), on the background budget of
`limitedWrapper` (Design §5), and
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

**Peer copies after a rewrap (eng D3).** A rewrap changes only `WrappedKey`,
but the peer receive path rejected same-generation, different-bytes copies
(`internal/store/store.go:5865-5870`), and the put-outbox resends the row's
current bytes. A `pkg/secrets` helper now compares two envelopes on every
field except `WrappedKey`. `PutClusterSecret` uses it at `:5865` and `:5888`:
same generation and same content is idempotent and **keeps the bytes already
on disk** (no rewrite; tomb and outbox transitions still apply), because each
node's own sweep owns rewrapping its own copies and a late, older copy must
never undo it (eng D20, outside voice OV1). A different payload is still a
conflict.

**PKCS#11 label rotation (eng D23).** Labels are per-node settings, so a
rotation is staged: (1) add label B to `SB_SECRET_PKCS11_DECRYPT_KEY_LABELS`
on every node, then confirm every member lists B in
`aerolvm_key_decryptable{backend,key}`; (2) set `SB_SECRET_PKCS11_KEY_LABEL=B`
on every node; (3) wait until every member reports stale = 0 **and**
`aerolvm_key_current{backend,key}` = B; (4) retire A. Both info gauges also
show in `sandboxd key status`. Vault and AWS KMS need none of this: their
versions are global.

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
  fails and the node has AWS KMS settings (whatever its sealing provider), it
  tries AWS KMS (an untagged `awskms` row). That keeps the two-step switch
  (eng D8) window-free for `local → awskms` too (eng D22, outside voice OV3). This replaces "untagged means `awskms`" (§4, E4) with
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
- **Two-step switch, no window (eng D8).** A node opens any tagged row whose
  backend it has settings for, whatever `SB_SECRET_PROVIDER` says; sealing
  still follows `SB_SECRET_PROVIDER`. The runbook: (1) add the new backend's
  settings (and key-store access) to every node, which changes nothing;
  (2) flip `SB_SECRET_PROVIDER` in a rolling restart. Every node can open the
  new rows before any node seals them, so no sandbox loses its failover copy
  during the switch.

### 13. Server-key rotation (eng D26)

**Why.** Wrapping keeps the same server key (§3), so copies made before a
migration still open data (claim, "Copies made before a migration"). Rotating
the key and resealing every row makes those copies useless for anything
sealed after the rotation, and answers the "how do you rotate data keys?"
audit question.

**Format.** `Cipher` output today is `nonce(12) || ciphertext+tag`
(`pkg/secrets/secrets.go:25-30`) with no key id. New writes are
`0xA1 || key_id(4 bytes) || nonce(12) || ciphertext+tag`. Reading tries the
key-id form first (look the id up in the ring) and falls back to the legacy
form under the ring's legacy key. GCM authenticates both attempts, so a
legacy blob that happens to start with `0xA1` fails the first try cleanly.
Legacy blobs read as key id 0.

**Key ring.** The server-key file becomes a ring: a list of keys, each with an
id, its wrapped (or, with `custody=file`, plain) bytes, its `check`, and a
state of `current`, `decrypt` or `retired`. Exactly one key is `current`. The
`key_custody` loop re-reads the file on every re-check, so a ring change
reaches a running node within about 5 minutes with no restart. Rotation works
with both custody modes; with `custody=wrapped` every ring key is wrapped by
the key store.

**Staged rotation** (the same pattern as eng D8 and D23):

1. `sandboxd key rotate --stage` makes key K2 and writes the ring with K1
   `current` and K2 `decrypt`. It refuses unless every alive member advertises
   the ring-format gossip feature version (`liveMembersAtLeast`,
   `internal/cluster/audit_caller_gate.go:46`), so no old binary ever meets a
   key-id blob. The operator copies the file to every node, as for the
   initial wrap.
2. When `aerolvm_server_key_ring{key_id,state}` shows K2 decryptable on every
   member, `sandboxd key rotate --promote` makes K2 `current`; nodes seal new
   data with K2 after their next re-read.
3. The `key_custody` loop reseals every sealed column under K2, paged and
   under compare-and-swap on the exact bytes it read: toolbox tokens, env,
   registry auth, mount credentials, the egress CA record, and `local`
   cluster-secret copies (peer copies follow eng D20: each node reseals its
   own, an older incoming copy never replaces a newer one).
   `aerolvm_server_key_rows{key_id}` counts what is left. This is local AES
   work only: the ring is already in memory, so it makes no key-store calls.
4. When every member reports zero rows on K1 and K2 `current`,
   `sandboxd key rotate --retire K1` marks K1 `retired` and drops its bytes
   from the ring.

After step 4, a copy of K1 (old backup, old cred bundle, old S3 object)
opens nothing sealed after the rotation, and nothing in the current
database. It still opens the old backup's own old rows, which no rotation can
change. The D24 "migrated from plaintext" notice clears on its own when the
plaintext-era key is retired.

**Revoke and recovery.** `Cipher.Revoke()` drops every ring key; auto-recovery
(eng D12) restores the ring from the file after a good unwrap and check of
the current key.

**Audit.** `key_rotation_staged`, `key_rotation_promoted` and
`key_rotation_retired` are new `Kind` values. Every node writes them when it
takes the step, at its next boot or re-read (not only the node that ran the
command), so each node's log shows when that node started sealing with the
new key.

## Coordination with other plans

- **`plans/kubernetes-deployment.md:181`** proposes
  `SB_SECRET_PROVIDER=kubernetes` to back the server key with a Kubernetes
  Secret. Recommendation: drop it. The wrapped server key file, mounted from a
  Secret, does the same job with an external key store behind it, and adds no
  new provider.
- **HSM signing of audit heads** (`plans/secrets-hardening.md:1014`, and
  `plans/open-audit-witness.md` Non-goals) can reuse the PKCS#11 session pool
  from Phase 3. Deferred to its TODOS.md entry (CEO-E6).
- **Cluster placement.** Untouched: eng D7 chose no placement change, so
  CLAUDE.md rule 6 does not apply to this stack.

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
- **`limitedWrapper`:** concurrency cap, backoff, context deadline, that
  background calls never take the foreground slots, and one retry of
  `ErrProviderUnavailable` for foreground calls only (a fake that fails once
  succeeds; one that fails twice returns 503; a background call never
  retries) (eng D17).
- **Error classes:** each backend's table (Design §1, §2, §10) maps to the
  right sentinel, including the `awskms` change for `Disabled` and
  `NotFound`, `KMSInvalidState` counted as a revoke only with
  `PendingDeletion` from `DescribeKey`, and the PKCS#11 rotation-window case
  (both labels gone → revoked).
- **Config:** cluster mode with `custody=wrapped` boots with the wrapped file
  and no plaintext key (`config.go:2573-2580` rewritten).
- **API errors (Section 2):** each provider class returns 503 with its stable
  code, `Retry-After` on throttling; no log line contains a request or
  response body from the key store. An end-to-end case opens a cluster
  secret whose key was revoked and checks the handler returns 503
  `key_revoked`, which needs `openRawEnvelope` (`pkg/secrets/envelope.go:255-260`)
  to pass `ErrKeyRevoked` and `ErrKeyVersionRetired` through instead of
  folding them into `ErrDecryptFailed` (outside voice OV7).
- **Custody report (§9):** a table test over config combinations for
  `sandboxd key status` and the gauge labels, including `software token`.
- **Revocation (§10):** the classifier per backend; N consecutive revokes
  trip, a non-revoke in between resets the count, a Vault 403 never trips;
  the shared `Cipher` stops working for both the store and the service; the
  `key_revoked` event kind; and recovery (eng D12): revoke → re-enable → the
  next good re-check restores the `Cipher`, re-sends the CA, returns health
  to ok and writes `key_recovered`.
- **Two-step switch (eng D8, D22):** a node still sealing `local` but holding
  the Vault settings opens a `vault:` row; a node still sealing `local` but
  holding AWS KMS settings opens an untagged `awskms` row; a node without the
  settings returns the "wrapped by X; node configured for Y" error.
- **Untagged rows (eng D9):** a table over local-only, KMS-only and mixed
  histories; every row opens.
- **Adoption (§12):** an untagged local row opens with the server key; an
  untagged `awskms` row falls through to AWS KMS; the sweep converts a local
  row and the payload is unchanged; a revoked `Cipher` opens neither.
- **Revoke ordering (Section 4):** a `Decrypt` paused after its AEAD load
  completes across a revoke; a fresh one after it returns `ErrKeyRevoked`.
- **Server-key rotation (eng D26):** a legacy blob and a key-id blob both open;
  a legacy blob starting with `0xA1` falls back cleanly; `--stage` refuses
  while any member lacks the feature version; each reseal loses to a racing
  writer of the same row; revoke drops every ring key and recovery restores
  them; a live UC runs stage → promote → reseal → retire on a 3-node cluster
  with a failover between every step, then shows an old backup's key opens no
  current row.
- **Peer copies (eng D3, D20):** `PutClusterSecret` with the same generation
  and only `WrappedKey` changed succeeds and keeps the bytes already on disk;
  a pre-sweep copy arriving after the receiver's sweep leaves the receiver's
  newer wrapping in place; a changed payload still returns
  `ErrClusterSecretPayloadConflict`.
- **Sweep (§11):** compare-and-swap loses to each of the five racing paths
  (new `Put`, repair reseal, incoming peer copy, delete or tombstone, reseal
  retirement); an already-current row is a no-op; the stale-rows gauge.
- **Vault correlation (E3):** the fake asserts `X-Aerol-Correlation-ID` on
  every call, and the fixed background id on boot, re-check and sweep calls.
- **Provider tags (§4):** a row wrapped by another provider returns the
  "wrapped by X; node configured for Y" error, not a bare decrypt failure.
- **Full stop (§10):** after a revoke, `clear_inspect_ca` reaches the
  gateway; a fake old gateway answering `unknown op` gets its unit restarted
  and no CA is resent (eng D4); an open keep-alive inspected connection is
  closed, an inject rule denies with `ReasonSecretMissing`, and a Sync during
  the revoke carries no secrets (eng D21); the gateway drops its CA once sandboxd has been gone past the
  bound it was sent, and keeps it across a short restart; open SSH and
  exec streams close, health reports degraded, and a retired version never
  trips a revoke.
- **PKCS#11 helper (eng D5, D25):** the helper exits mid-call → the caller gets
  `ErrProviderUnavailable`, sandboxd restarts it with backoff and the next
  call succeeds; a fake helper that never answers is killed and replaced
  after the 5 s deadline, and the restart counter records `deadline`; the socket is 0600; the daemon process never maps the
  vendor library (checked through `/proc/self/maps` in a tag-gated test).
- **PKCS#11 (§2):** enterprise mode refuses a non-hardware slot; re-login
  after a reopened session; the label mapping (current missing → revoked,
  decrypt-only missing → retired, unknown → decrypt failure).
- **Security (Section 3):** `--generate` refuses on a joiner (S5); a custody
  change between boots writes `key_custody_changed` (S7); a Vault key name
  with `/` or `..` is refused (S9).
- **Migration notice (eng D24):** after `sandboxd key wrap` on an install with
  a plaintext key, `key status` reports "migrated from plaintext" until
  `key ack-migration`; the backup script with `custody=wrapped` archives no
  plaintext key.
- **`sandboxd key`:** `unwrap --to-file` round-trips to the same key and
  refuses without `--i-understand-plaintext`; `wrap --generate` refuses when any key exists; env-file
  loading order; the daemon never generates in cluster mode or with an
  existing `state.db`; a joiner without the wrapped file refuses to start.

**Regression contract (eng D15).** Existing behavior is protected by new rows
in the existing table tests, with existing rows unchanged:

| Behavior | Preserve | Intended difference |
|---|---|---|
| `awskms` error mapping (`TestMapAWSKMSError`) | Throttled, AccessDenied, other codes | Disabled, NotFound, InvalidState with PendingDeletion → `ErrKeyRevoked` |
| API error classes (`classify_test.go`) | every non-provider status | five provider classes → 503 with stable codes |
| `PutClusterSecret` (put-outbox and store tests) | stale generation rejected; tomb rules; payload conflict | same generation, only `WrappedKey` changed → idempotent |
| Upstream wrap key loader (`wrap_key_loader_test.go`) | 0400 required; looser or writable refused | none |
| `custody=file`, `local` provider (`secrets_test.go`, `config_test.go`) | `NewCipher` env/file/generate; cluster key check | none |
| `awskms` create path (provider contract run) | same results | passes through `limitedWrapper` |

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
  - the four-step PKCS#11 label rotation on the SoftHSM2 scenario, with a
    failover between every step (eng D23);
  - a joiner without the wrapped file refuses to start;
  - a fresh cluster built with `cluster-init.sh` / `cluster-join.sh
    --key-custody wrapped` (through the Terraform `key_custody` variable, since
    the itest reuses the prod module), and a single node with `install.sh
    --key-custody wrapped`: no plaintext key in the key file, `cluster.env`,
    the cred bundle or the S3 bundle object;
  - backup, then restore onto a fresh node with the key store reachable; the
    new backup holds no plaintext key line or key file (eng D24);
  - switch a running 3-node `local` cluster to `vault`: fail over a sandbox
    sealed before the switch, once before the sweep converts it and once after
    (CEO-M1);
  - the same two-step switch from `local` to `awskms`, with a create during
    the rolling restart failing over to a not-yet-switched node (eng D22).

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
- **Rotation runbooks:** `key-custody.mdx` and
  `setup/runbooks/secrets-and-audit.md` cover the server-key rotation (stage,
  promote, reseal, retire; eng D26), the PKCS#11 label rotation (eng D23)
  and the migration cleanup checklist (eng D24).
- **Vault Agent example:** `key-custody.mdx` shows an Agent config for both
  auth modes (token file, API proxy). Config files are allowed; raw HTTP is
  not.
- **Rule:** name only vendors that passed Phase 6. Everything else is "any HSM
  with PKCS#11 v2.40 AES-GCM; not yet tested".

## Phases

One PR per phase, stacked, with nothing merged until the whole stack is green.

| Phase | What | Effort |
|---|---|---|
| 0 | **Spike, no product code.** On Vault and OpenBao: decrypt with the wrong AAD is rejected; the error text for a deleted key and for a retired version; audited request headers record `X-Aerol-Correlation-ID`. On SoftHSM2 and CloudHSM: GCM IV behavior, `CKF_HW_SLOT`, and whether AES-GCM is available (eng D16 builds the key-wrap fallback only if a target lacks it). Choose miekg or crypto11. Measure p50, p99 and throughput for AWS KMS, Vault and CloudHSM from one region. Record the results in this file. | S (plus about 2 hours of CloudHSM) |
| 1 | **Seam split.** `secrets.NewWrapper(ctx, opts)` builds the wrapper from config with no store, and `NewProvider` takes it. Add the `limitedWrapper` decorator with its background budget, the provider tags, the `ErrKeyRevoked` and `ErrKeyVersionRetired` sentinels (and the `awskms` mapping change), the boot canary and strict-boot option for every external provider (the enterprise **requirement** lands in Phase 5), the cluster-mode key check at `config.go:2573-2580`, the reserved create slot, the provider-error to HTTP 503 mapping in `apihttp.WriteStoreAwareError` (Section 2), and the config validation. No other behavior change for `local` or `awskms`. | S |
| 2 | The `vault` wrapper and its tests, including the correlation header (CEO-E3). | M |
| 3 | The `pkcs11` wrapper, the `--pkcs11-helper` process with its socket protocol and supervisor (eng D5), the session pool, tests, plus a CI run of every `sandboxd` release-matrix target with the new cgo dependency (eng Scope Challenge finding 4). | L |
| 4 | (Shipped as two stacked PRs, 4.1 the wrapped key and 4.2 revocation, to keep each reviewable.) Wrapped server key: boot order in `pkg/daemon`, the revocable `Cipher`, `sandboxd key wrap [--generate]/rewrap/verify/status/unwrap` with env-file loading, `--key-custody wrapped` in `cluster-init.sh`, `cluster-join.sh`, `install.sh` and the Terraform bootstrap (`key_custody` variable, `bootstrap.sh.tftpl`) (fact 10), the joiner refusal, the backup and restore scripts, the custody gauge (CEO-E1), the revocation re-check with auto-recovery (CEO-E2, eng D12), and the full-stop pieces: `clear_inspect_ca` (drops the CA and injection secrets, closes inspected connections; eng D21) with the restart fallback for an old gateway (eng D4), closing proxied sessions, degraded health (CEO-E2R). | L |
| 4b | Rewrap sweep (CEO-E4): in-daemon sweep with compare-and-swap, the stale-rows gauge, `ErrKeyVersionRetired` handling, local → external conversion with the untagged-row open order (CEO-M1, Design §12), and the peer-copy comparison without `WrappedKey` (eng D3). | L |
| 4c | Server-key rotation (eng D26): key-id `Cipher` format with authenticated dual read, the key ring, `sandboxd key rotate --stage/--promote/--retire` gated on gossip feature version, the reseal pass in the `key_custody` loop for every sealed column, the ring gauges and the rotation audit kinds. | XL |
| 5 | Enterprise rules, the docs page and updates, config-defaults, the runbook, the `SandboxdServerKeyPlaintext`, `SandboxdKeyRevoked`, `SandboxdKeyVersionRetiredInUse` and `SandboxdKeyStoreThrottling` alerts with runbooks and `alerts_test.go` rows (CEO-E1, CEO-E2, CEO-E4, Section 8), the key-custody Grafana row, the revoke procedure per backend, and the Vault Agent example. | S |
| 6 | The tag-gated CI job, the live itest scenarios, the CloudHSM run, and an Outcome section here. | M (AWS time) |
| 7 | **One release later (F2):** enterprise mode with an external provider refuses `custody=file`; release notes announce it one release ahead. *(Built, held for the release after the stack: see "Phase 7 status".)* | S |

Phase 1 also rewrites the reject at `internal/config/config.go:2599-2602` and
the comment at `pkg/secrets/factory.go:38-40`. The `vault` value keeps
refusing to boot until Phase 2 lands in the same stack.

## Phase 0 results (2026-10-30)

Run locally in Docker against Vault 1.18 and OpenBao 2.1 dev servers and
SoftHSM2 2.6.1 (Debian bookworm), with `github.com/miekg/pkcs11` v1.1.1. The
probe programs were throwaway and are not in the repo. CloudHSM and AWS-region
latency are operator-run (they cost money) and stay open in the gate table.

**Vault and OpenBao (identical results):**

| Check | Result |
|---|---|
| encrypt with `associated_data` | 200 |
| decrypt with the right AAD | 200, plaintext matches |
| decrypt with a wrong or missing AAD | 400 `cipher: message authentication failed` → `ErrDecryptFailed`; no derived-key fallback needed |
| `rewrap` with `associated_data` | 400 `cipher: message authentication failed` (confirms eng finding 2) |
| decrypt after the key is deleted | 400 `encryption key not found`, also with an `update`-only token → `ErrKeyRevoked` |
| decrypt below `min_decryption_version` | 400 `ciphertext or signature version is disallowed by policy (too old)` → `ErrKeyVersionRetired` |
| `min_decryption_version` above latest | 400 `cannot set min decryption version of 5, latest key version is 2` |
| encrypt after the key is deleted | root token: 200 and the key is **silently recreated**; `update`-only token: 403 `permission denied`, key stays deleted → new boot check (§1 "Least privilege, checked") |
| audited request header | `x-aerol-correlation-id` recorded in the audit log with `hmac=false` |
| `read` on `keys/<key>` | returns `latest_version` and `min_decryption_version` |
| encrypt latency, loopback Docker on macOS | Vault p50 2.0 ms / p99 7.6 ms; OpenBao 1.5 / 5.5 ms (not the AWS-region number) |

**SoftHSM2:**

| Check | Result |
|---|---|
| `CKF_HW_SLOT` | false → enterprise refuses it, as designed |
| `CKM_AES_GCM` / `CKM_AES_KEY_WRAP_PAD` | both available → no fallback needed (eng D16) |
| caller-supplied IV | accepted |
| zeroed IV buffer | **not filled; encrypts with the all-zero IV** → IV mode is now probed at helper start and an all-zero IV is always refused (§2) |
| wrong AAD on decrypt | `CKR_GENERAL_ERROR`, not `CKR_ENCRYPTED_DATA_INVALID` → mapped to `ErrDecryptFailed` after a successful `C_DecryptInit` (§2) |
| second `C_Login` | `CKR_USER_ALREADY_LOGGED_IN` → treat as success |
| after every session closes | login is lost and private keys are **invisible** (label not found) → "label not found" is a revoke only while logged in (§2) |
| destroyed key | label search finds nothing; a cached handle returns `CKR_OBJECT_HANDLE_INVALID` |

**Unverified premises after Phase 0:** Vault Agent's API proxy injecting the
token (tested in Phase 2), and the CloudHSM rows above.

## Phase 6 results (2026-10-31)

All three live scenarios passed from fresh clusters in one run each, and the
AWS CloudHSM run passed. Every AWS resource was torn down afterwards.

| Run | Result |
|---|---|
| `cluster-3-mixed-secrets-vault` (UC-297..306) | 10/10 pass, about 33 min of suite on a new 3-node cluster |
| `cluster-3-mixed-secrets-pkcs11` (UC-307..309) | 3/3 pass, about 17 min |
| `cluster-3-mixed-wrapped-kms` (UC-310) | pass, with a real failover |
| AWS CloudHSM, `hsm2m.medium`, FIPS mode, one HSM | `TestPKCS11Live` pass: hardware slot, IV mode `hsm` (the HSM writes the GCM IV), AAD, missing label = revoke, label rotation, 64 concurrent round trips through the helper in 182 ms with the library mapped only there. A real `sandboxd` generated a wrapped key, booted through CloudHSM, and took a server-key stage, promote and retire live. |

- **Tag-gated CI job** `key-custody-integration`: Vault 1.18 and OpenBao 2.1
  dev servers (images pinned by digest) running `TestVaultLive` and
  `TestVaultProviderContract`, and SoftHSM2 running `TestPKCS11Live`.
- **What the live runs found:** no product bug. Seven fixture bugs, all
  fixed: a glob in a root-only directory (it would have passed UC-298 and
  UC-310 falsely), a marker check that could not see its own markers (and so
  restarted the in-memory OpenBao and wiped its key), port 8200 closed
  between nodes, keep-alive connections pinned to the stopped node, failovers
  skipped when the sandbox sat on the seed, a proxy token gone stale after
  an OpenBao restart, and `softhsm2-util --import` dropping whitespace bytes
  from a key file. Also #805's `key_custody` missing from the Terraform
  render fixture.
- **CloudHSM notes for the docs:** module
  `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`, token label `hsm1`, PIN file
  `<crypto user>:<password>`; a one-HSM cluster refuses key operations
  unless the client disables the key availability check. AWS had no
  `hsm2m.medium` capacity in us-east-1a; us-east-1b worked.
- **Deviations.** The OpenBao server is a dev server with TLS (in memory) and
  OpenBao Proxy, not Raft storage and Agent: no case restarts it, and Agent's
  token-file mode was covered in Phase 2. The eng D22 case is a follow-up.

**Coverage gaps (2026-10-31).** A review of the test list above against the
tests found 12 items covered and 20 partly covered. Every unit-level gap is
now closed (branch `feat/key-custody-6b-test-gaps`, stacked on Phase 6):

- the sweep loses to each of the five racing writers (new `Put`, repair
  reseal, peer copy of a newer and of the same generation, delete with and
  without a tombstone, reseal retirement), and does not hold the sandbox lock
  across the key-store call; a `Decrypt` in flight across a revoke;
- the full stop: a gateway Sync while revoked carries no secrets and no CA,
  an old gateway's restart gets no CA, an inject rule refuses with
  `secret_missing` after `DropSecrets`, recovery re-sends the CA and the
  secrets and health returns to ok; a real v1 handler answers 503
  `key_revoked` with nothing sealed in the response or the log; a Vault
  error never carries a request or response body;
- the PKCS#11 helper killed mid-call (exit, not deadline) and a successful
  call after the restart and after a deadline replacement;
- the D9 history table, sweep correlation ids on every call, the AWS KMS
  contract through the limiter, the remaining config rows, and the boot
  order (the database is not opened when the key store refuses).

The gap review found two product gaps, both fixed on the same branch:

- **eng D8 step 1 did not work from `local`.** A node with
  `SB_SECRET_PROVIDER=local` ignored the key-store settings: it built no
  client and `LocalProvider.Open` used the server key only, so a failover
  onto a node not yet flipped could not open a row a switched peer sealed.
  Such a node now gets an open-only client (`secrets.NewOpenWrapper`) and
  opens through the same path a switched node uses; without the settings it
  names the key store it lacks. The live UC-297 never hit this because its
  failovers run after every node has flipped.
- **`software token` was only a log line (§2).** The custody report takes
  the running token's slot kind: `aerolvm_key_custody` reads
  `pkcs11 (software token)`, and `sandboxd key status --check` prints it.

**Live gaps (2026-10-31, branch `feat/key-custody-6c-live-gaps`).** Run on
four fresh clusters, all torn down afterwards:

| UC | Scenario | Result |
|---|---|---|
| UC-311 AWS KMS key disabled → full stop (gauge, health, audit, an open exec stream closes, 503 `key_revoked`) → re-enabled → recovery and a failover | `cluster-3-mixed-wrapped-kms` | pass |
| UC-312 the two-step switch from local to AWS KMS (eng D22), with a failover from a switched node to one still sealing locally | new `cluster-3-mixed-kms-switch` | pass (373 s): the step-1 fix, live |
| UC-313 env, registry and mount secrets come back after a failover (TLS + htpasswd registry and an SSHFS share on the seed) | `cluster-3-mixed-secrets-vault` | pass |
| UC-314 a backup restored onto the wiped node boots through the key store and rejoins; its next backup holds no plaintext key | vault | pass (146 s) after a test fix |
| UC-315 one node installed with `install.sh --key-custody wrapped` | new `single-node-wrapped-kms` | pass |
| UC-304 now also checks that a pre-rotation copy of the wrapped file holds only the retired key | vault | pass |
| UC-305 restart with the plan's 50 secret-bearing sandboxes (0.25 CPU, 256 MB each): all open, no throttled call | vault | pass |
| UC-301 key store down at boot | vault | **failed, then fixed**: see below; pass (165 s) |

UC-301 found a third product gap: the unit `install.sh` writes stops
restarting after 10 failed starts in 5 minutes, and the healthcheck skipped a
unit that was not active, so a node whose key store was down for more than
about 50 s at boot never came back. The healthcheck now starts a failed unit
again every 30 s (see the correction under "Failure rule"), and UC-301 takes
that path on purpose.

Deviations: "restore onto a fresh node" restores onto the same machine
after wiping everything the backup covers (the suite cannot add a node);
"a fresh joiner" is covered by UC-310, whose joiners are built wrapped; the
SSH-session half of the full stop and the alert itself stay unit-tested
(the alert's condition, `aerolvm_key_revoked == 1`, is asserted live).

A full local `go test ./...` on the stack (CI runs no Go job on a PR that
targets another stack branch) found `pkg/caddy`'s install.sh render test
failing since the wrapped-key phase: its prelude lacked `KEY_CUSTODY`.
Fixed on this branch.

Follow-up (not a key-custody regression): on a joiner, install.sh starts
sandboxd standalone before cluster-join.sh, and with `--key-custody
wrapped` that first boot takes the "fresh single node, generate" path; the
join restarts it within seconds (one live run caught it cancelled mid-wrap)
and installs the seed's wrapped file over anything it wrote. Nothing is
sealed in that window, and the plaintext install has the same
standalone-first boot, but install.sh could skip starting sandboxd when a
join follows.

## Phase 7 status (2026-10-31)

Built on `feat/key-custody-7-enterprise-refuses-file`, stacked on Phase 6's
live-gap branch, and **held**: by decision F2 it merges one release after
the rest of the stack ships, whose release notes announce it.

- **Config.** With `SB_ENTERPRISE_MODE=true` and an external
  `SB_SECRET_PROVIDER`, `SB_CREDENTIAL_KEY_CUSTODY` must be `wrapped`; the
  error names `sandboxd key wrap`. `sandboxd key` still loads such a config,
  since it is how a node gets to `wrapped`. The local provider is not
  refused (it has no key store to wrap with); `SandboxdServerKeyPlaintext`
  still covers it.
- **Removed** the first-release boot warning (`enterpriseCustodyWarning`):
  a node it would warn about no longer starts.
- **Scenarios.** `cluster-3-mixed-secrets-enterprise`,
  `cluster-hetero-lite-kms` and `cluster-hetero-secrets-kms` run enterprise
  mode on AWS KMS, so they are built with `key_custody = "wrapped"`.
- **Docs.** The key-custody page, the runbook, the alert text and
  `setup/config-defaults.md` say "refused" instead of "the next release
  refuses".
- **Test.** `TestEnterpriseRequiresWrappedCustodyWithAKeyStore`: refused
  with a key store and a plaintext key; the key tool, wrapped custody and the
  local provider still load.
- **Live (2026-10-31).** `cluster-3-mixed-secrets-enterprise` built wrapped
  on this build: UC-310 passes (no plaintext key anywhere, failover). A node
  overridden to custody `file` with a plaintext key set refused at config
  load with the message above, and came back once the override was removed.

## Phase 5 results (2026-10-31)

- **Enterprise rules (§7).** Strict boot is required for every external
  provider, not only `awskms`. An enterprise node with an external provider
  and custody `file` logs a warning at boot and fires
  `SandboxdServerKeyPlaintext` (F2, first release; Phase 7 refuses it). The
  hardware-slot rule shipped in Phase 3.
- **Metrics (Section 8).** Added the two key-store call metrics Phase 1 left
  out: `aerolvm_key_store_calls_total{key=backend,key2=op,key3=class}` and
  `aerolvm_key_store_call_seconds_bucket{key="<backend>_<op>"}`, reported by
  the router for every backend call, plus one OTEL span per call
  (`key_store.wrap` / `key_store.unwrap`, backend and class attributes,
  never key bytes).
- **Alerts.** A `sandboxd.key-custody` group with
  `SandboxdServerKeyPlaintext`, `SandboxdKeyRevoked` (critical),
  `SandboxdKeyVersionRetiredInUse` and `SandboxdKeyStoreThrottling` (over 5%
  of one backend's calls throttled for 15 minutes); `promtool check rules`
  passes; `TestKeyCustodyAlertRules` checks severities, registered metrics,
  positional labels and runbook anchors.
- **Runbook.** `setup/runbooks/secrets-and-audit.md` gains a Key custody
  section: one entry per alert, the revoke procedure per backend, both
  rotations (key-store key incl. the four-step PKCS#11 label rotation, and
  the server key) and the migration cleanup checklist.
- **Dashboard.** A Key custody row in `d9-security-isolation.json`, checked by
  `TestKeyCustodyRowMetricsAreRegistered`.
- **Docs.** New page `enterprise/key-custody.mdx` ("Use your own key store"),
  registered in the Enterprise tab's Security group rather than the Docs
  sidebar, whose cluster-operations group is commented out; it sits next to
  SSO. It ends with the five-language SDK section. The pages the Docs list
  names, plus `cluster-glossary`, `engineering-security-overview`,
  `engineering-trust-boundary` and `enterprise-mode`, no longer say "AWS KMS
  only" or "Vault not built yet". Vendor naming follows the rule: Vault 1.18
  and OpenBao 2.1 (tested live), HSMs as "any PKCS#11 v2.40 AES-GCM HSM; not
  yet tested on hardware".

## Phase 4c results (2026-10-31)

Server-key rotation (§13, eng D26) as designed: the key-id `Cipher` format
with authenticated dual read, the ring (format 2 of the wrapped file; for
custody `file` a plaintext ring file at `SB_CREDENTIAL_KEY_RING_PATH`),
`sandboxd key rotate --stage/--promote/--retire ID`, the ring re-read and the
reseal pass in the key-custody loop, `aerolvm_server_key_ring{key,key2}`,
`aerolvm_server_key_rows{key}` and the three rotation audit kinds.

Live on a real `sandboxd` + Vault 1.18 (single node, 10 s re-check), with 8
values sealed through the real store (toolbox token, registry auth, mounts,
env on two sandboxes), no restart between steps: the staged key showed on the
ring gauge 10 s after `--stage`; 10 s after `--promote` all 8 values were on
key 1 (`aerolvm_server_key_rows{key="1"} 8`); after `--retire 0` the rows
gauge cleared. Offline, the new ring opened all 8 on key 1, and a copy of key
0 taken before the rotation opened none of them. The node then rebooted from
the ring file, and its audit log held one `key_rotation_staged`, one
`_promoted` and one `_retired` record.

Decisions made while building it:

- **Who writes the rotation records.** Every node, as it takes each step
  (§13 Audit updated), not only the node that ran the command.
- **The stage gate.** `fsmOpsVersion` 4, with `ServerKeyRingFSMOpsVersion`
  naming it. The CLI cannot see gossip, so `GET /v1/cluster/members` now
  also returns `server_key_ring_ready` (the gossip gate with its boot-window
  rule); a daemon that predates it, an unreachable daemon, a lagging member
  or a node that has not rejoined all refuse the stage.
- **One rotation at a time.** `--stage` refuses while any key is
  decrypt-only. Retiring a staged key that was never promoted cancels the
  rotation. Key ids are never reused.
- **custody `file`.** The ring file, once written, holds every live key; a
  key in `SB_CREDENTIAL_ENCRYPTION_KEY` or the key file must match ring key 0
  while key 0 is live, and boot warns when it is still there after key 0 is
  retired. The cluster shared-key check accepts the ring file. Backups carry
  it; `cluster-join.sh` installs one found in the cred bundle.
- **Lost updates.** A whole-row sandbox write carries a registry blob read
  earlier; during a rotation the store moves it onto the current key before
  writing, so a write that raced the reseal pass cannot put the old key's
  bytes back. The daemon's rewrap and `sandboxd key rotate` both edit the
  server-key file; each writes only if the file is unchanged since its read
  (`ErrKeyFileChanged`).
- **Counting.** A value that lost its compare-and-swap is counted under the
  key it was read on until the next pass looks again, so the rows gauge
  never reaches 0 early; values no ring key opens are counted as
  `unopenable`. With one key in the ring the pass reads nothing.

Not done here: the rotation runbook and alerts (Phase 5), the 3-node live UC
with a failover between every step (Phase 6). Rolling a node back to a build
before this one is not possible once a key is promoted: its rows name their
key.

## Phase 4b results (2026-10-31)

The rewrap sweep runs in the key-custody loop: at boot (after the API is up)
and hourly after a random start delay. It moves this node's rows, and its
server-key file, onto the sealing provider's current key under
compare-and-swap, converts local rows after a `local → external` switch, and
counts what is left in `aerolvm_key_rows_stale` and rows on a retired version
in `aerolvm_key_rows_retired`. `PutClusterSecret` treats a same-generation
copy that differs only in `WrappedKey` as the same secret and keeps the bytes
on disk (eng D3, D20). An untagged row opens with the server key first, then
AWS KMS (§12, eng D22).

Live on a real `sandboxd` + Vault 1.18 (single node, so no cluster rows):
after a Transit rotation the boot sweep rewrapped the server-key file
(`vault:v1 → vault:v2`), and with v1 then retired the node still booted.
Cluster rows are covered by unit tests over a Transit-like versioned store
(paging past one page, conversion, rotation, retirement, key-store failure
mid-pass); the cluster run is Phase 6.

## Phase 4 results (2026-10-31)

Shipped as two stacked PRs. Both were run live on a real `sandboxd` against a
Vault 1.18 dev server in a Linux container.

**4.1, the wrapped server key:** a fresh single node wrote only
`credential_encryption.key.wrapped` (0600, `vault:v1`); a restart reopened the
same key; a plaintext key file left behind stopped the boot (F1); `sandboxd key
unwrap --to-file` followed by a `file`-custody boot wrote `key_custody_changed`
(S7); with the Transit key deleted, boot failed with `key revoked by the key
store`. The run caught one bug (a spurious first-boot warning), fixed before
the PR.

**4.2, revocation:** with a 10 s re-check and `REVOKE_AFTER=2`, the node
stopped 20 s after the Transit key was deleted (health `key_custody: revoked`,
`key_revoked` audit record) and resumed 10 s after the key was restored from a
Transit backup (`key_recovered`). The egress gateway path (`clear_inspect_ca`,
the restart of an older gateway, the self-drop after the bound) is covered by
unit tests; the container run had no gateway.

One addition to §3: custody `file` with only a wrapped key present refuses to
boot instead of minting a fresh plaintext key that would orphan every row.

## Phase 3 results (2026-10-31)

`pkg/secrets/pkcs11` (eng D5, D6): the helper process, its socket protocol and
supervisor, the session pool and the §2 error table, with a `!cgo` stub.

| Check | Result |
|---|---|
| `TestSoftHSM` (SoftHSM2 2.6.1, Debian bookworm container) | wrap and unwrap, fresh non-zero IVs, `auto` → `caller`, `CKF_HW_SLOT` false, wrong AAD → `ErrDecryptFailed`, decrypt-only key destroyed → `ErrKeyVersionRetired`, current key destroyed → `ErrKeyRevoked` |
| `TestVendorLibraryStaysInHelper` | `libsofthsm2.so` is in the helper's `/proc/<pid>/maps` and not in the parent's |
| `sandboxd` boot with `SB_SECRET_PROVIDER=pkcs11` on SoftHSM2 | helper started, software-token warning, `secret provider boot canary ok provider=pkcs11` |
| `go build ./cmd/sandboxd` with cgo | linux amd64, 386, arm64, armv7, armv6 (cross gcc in Docker) and darwin arm64 all build; CI runs the same matrix (`sandboxd-cgo-matrix`) |

One design change from §2 as reviewed: the IV probe uses a throwaway session
key (see "The IV" above). Sessions are opened read-write because the probe
creates and destroys that key.

## Phase 2 results (2026-10-31)

`TestVaultLive` (`pkg/secrets/vault_integration_test.go`, `integration` build
tag) against Vault 1.18 and OpenBao 2.1 dev servers in Docker, each through
both `agent` and `proxy` with `api_proxy { use_auto_auth_token = "force" }`
and `token_file` auto-auth. All four runs pass:

| Check | Result |
|---|---|
| canary with an `update`-only token from a token file | ok |
| decrypt with the wrong encryption context | `ErrDecryptFailed` |
| boot with the root token, or a token with `create` on the encrypt path | refused (`IsVaultPolicyError`) |
| open through the Agent or Proxy listener, no token in sandboxd | ok: the proxy premise holds |
| decrypt below `min_decryption_version` | `ErrKeyVersionRetired` |
| decrypt after the key is deleted | `ErrKeyRevoked` |
| encrypt after the key is deleted, `update`-only token | `ErrProviderDenied`, and the key is not recreated (404) |

Two findings for the Phase 5 docs. Vault 1.18 and OpenBao 2.1 both log that
Agent's API proxy is deprecated in favor of the `proxy` subcommand, so the
docs show `vault proxy` (`bao proxy`) for the no-token mode and Agent only for
the token-file mode. Agent's `token_file` auto-auth needs `lookup-self` from
the `default` policy, and the boot check needs `sys/capabilities-self` (also in
`default`), so the documented policy keeps `default` or grants both.

## Decisions needed

Each open question blocks a named phase. A phase does not start until its
gates are answered and written back here.

| Question | Owner | Blocks |
|---|---|---|
| ~~F1 plaintext-present refusal~~ answered: refuse (D13) | founder | — |
| ~~F2 enterprise requires `wrapped`~~ answered: warn, then refuse (D16) | founder | — |
| ~~F3 first HSM to certify~~ answered: AWS CloudHSM (D14) | founder | — |
| ~~E1 Vault auth modes~~ answered: Vault Agent only (eng D10) | — | — |
| ~~E2 thin Vault client~~ answered: thin client (eng D11) | — | — |
| ~~E3 key-wrap-pad fallback~~ answered: only if Phase 0 finds a target HSM without AES-GCM (eng D16) | — | — |
| ~~E4 untagged rows~~ answered: local first, then `awskms` (eng D9) | — | — |
| ~~E9 rolling-switch window~~ answered: two-step switch, no window (eng D8) | — | — |
| ~~E5 limiter settings~~ answered: only `SB_SECRET_PROVIDER_MAX_INFLIGHT` (eng D13) | — | — |
| ~~CEO-E2a recovery~~ answered: auto-recover on a good re-check (eng D12) | — | — |
| ~~CEO-E2b placement awareness~~ answered: none (eng D7) | — | — |
| ~~CEO-E2c re-check defaults~~ answered: 5 min × 3 (eng D18) | — | — |
| ~~CEO-E2e older egress gateway after an upgrade~~ answered: restart the gateway unit on `unknown op` (eng D4) | — | — |
| ~~E6 PKCS#11 in-process or helper~~ answered: helper process (eng D5) | — | — |
| ~~E7 PKCS#11 package~~ answered: `pkg/secrets/pkcs11` with a `!cgo` stub (eng D6) | — | — |
| ~~E8 short retry on Unavailable~~ answered: one jittered retry, foreground only (eng D17) | — | — |
| ~~CEO-E4a sweep cadence~~ answered: boot + hourly (eng D19) | — | — |
| ~~CEO-E4b no cross-node sealed-byte comparison~~ found one (`store.go:5865`); fixed by comparing without `WrappedKey` (eng D3) | — | — |
| ~~Phase 0: Vault and OpenBao reject a wrong AAD on decrypt~~ answered: yes, 400 `cipher: message authentication failed` on both (Phase 0) | — | — |
| ~~Phase 0: miekg vs crypto11~~ answered: `github.com/miekg/pkcs11` v1.1.1 (Phase 0) | — | — |
| Phase 0: CloudHSM sets `CKF_HW_SLOT`, fills a zeroed IV buffer, and offers AES-GCM (SoftHSM2 answered: no HW flag, no IV fill, GCM yes) | operator-run CloudHSM (costs money) | Phase 6 enterprise claim for CloudHSM |
| ~~Phase 0: Transit `rewrap` accepts `associated_data`~~ answered: no (vault issue #29532); the sweep decrypts and re-encrypts (eng finding 2) | — | — |
| ~~Phase 0: audited request headers record `X-Aerol-Correlation-ID`~~ answered: yes on both with `hmac=false` (Phase 0) | — | — |
| ~~Phase 0: Vault error text~~ answered: deleted key `encryption key not found`; retired version `ciphertext or signature version is disallowed by policy (too old)` (Phase 0) | — | — |
| Phase 0: create-path wait under a restart storm, with the reserved slot (fake-backend benchmark in Phase 1; AWS numbers in the operator run) | Phase 1 benchmark + operator run | Phase 1 |
| Phase 0: AWS-region latency and throughput for AWS KMS, Vault and CloudHSM (loopback only so far: Vault p50 2.0 ms / p99 7.6 ms, OpenBao 1.5 / 5.5 ms) | operator-run | Phase 6 sizing docs |
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
  **Answered 2026-10-25 (eng D10): yes.**
- **E2.** Thin Vault client instead of `hashicorp/vault/api`? **Answered
  2026-10-25 (eng D11): thin client.**
- **E3.** Ship the PKCS#11 key-wrap-pad fallback? **Answered 2026-10-25 (eng
  D16): only if Phase 0 finds a target HSM without AES-GCM.**
- **E4.** Untagged rows: try the server key (local) first, then `awskms`.
  **Answered 2026-10-25 (eng D9).**
- **E5.** Put `limitedWrapper` defaults in config now, or hard-code them?
  **Answered 2026-10-25 (eng D13): only `SB_SECRET_PROVIDER_MAX_INFLIGHT` is
  a setting; the rest are commented constants.**

## Follow-ups (not in this plan)

- ~~**F-R1:** a rewrap sweep~~ Now in scope as Design §11 (CEO-E4).
- Live provider switching: a decrypt-only previous provider plus a reseal.
- ~~Server key (data key) rotation~~ now in scope as Design §13 (eng D26).
- The eng D22 live case: switch a running `local` cluster to `awskms` with a
  create during the rolling restart that fails over to a node not yet
  switched (needs a scenario that boots local with a KMS key).
- Not in the test list, found in review: split reachability (some nodes
  reach the key store, others do not); Firecracker, WASM, isolate and gVisor
  sandboxes under wrapped custody and revoke; enterprise mode with wrapped
  custody end to end; a mixed-version rolling upgrade through the fv 4 gate,
  live; the create-latency cost of each key store; the reseal pass over
  100k rows; Vault token expiry and renewal, and Vault HA standby failover.
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
          ^                ^ TLS, or Vault Agent       ^ vendor .so + session pool, in the
          |                | proxy on loopback         | --pkcs11-helper process over a 0600
          |                |                           | socket (eng D5); pkg/secrets/pkcs11 (D6)
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
  key_custody loop (eng D2):     revocable *Cipher (one, shared) ---> store: toolbox
  re-check, revoke, recover,           |                              tokens, env, ...
  sweep (CAS)
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
| Vault | active-node failover returns 503 for seconds | creates with secrets fail fast as Unavailable. **Gap**: no short retry for Unavailable (answered: one retry, eng D17) |
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
ErrProviderUnavailable   | Y        | one jittered retry, foreground only (D17) | 503 "key store unavailable"
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
| S4 | Vendor PKCS#11 library runs inside sandboxd: a crash takes the daemon down, a bug can read its memory | Low | High | **Mitigated (eng D5):** the library runs only in the supervised `--pkcs11-helper` process |
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
| Revoke | key disabled for 20 minutes, then re-enabled | yes | trips; the next good re-check auto-recovers (eng D12) |
| Restore | backup restored onto a fresh node | yes | backup includes the wrapped file; key store must be reachable |
| Upgrade | sandboxd new, egress gateway still old | pending | CEO-E2e |

#### Section 5: Code quality

- **Where the code goes** (fits existing patterns): `pkg/secrets/vault.go`,
  `limited.go`, `custody.go` (the wrapped-file format and boot decision), the
  revocable AEAD inside `secrets.go`; PKCS#11 in `pkg/secrets/pkcs11` with a
  `!cgo` stub (eng D6), like `pkg/wasm` keeps wasmtime behind a tag; the re-check, revoke, recover and sweep as one
  loop in `internal/service/key_custody.go` with two cadences (eng D2: one
  owner of the server key's lifecycle); the `sandboxd key` subcommand in
  `cmd/sandboxd/key.go`, dispatched from `cmd/sandboxd/main.go` like
  `egress-gateway`.
- **Reuse, not copies.** `encryptionContextAAD` moves out of `fake_kms.go`
  (already planned). The group/other permission check in
  `wrap_key_loader.go:72` becomes `refuseGroupOtherBits(path)`, used by the
  upstream wrap key, the PIN file and the wrapped server-key file (eng D14);
  the upstream key keeps its stricter write-bit check (`:75`) inline, because
  sandboxd itself rewrites the wrapped file at 0600.
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
  `aerolvm_key_rows_stale`, `aerolvm_key_revoked`,
  `aerolvm_key_decryptable{backend,key}` and `aerolvm_key_current{backend,key}`
  (eng D23), `aerolvm_pkcs11_helper_restarts_total{reason}` (exit,
  deadline; eng D25), and `aerolvm_server_key_ring{key_id,state}` and
  `aerolvm_server_key_rows{key_id}` for server-key rotation (eng D26). Names follow the existing
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
active-node failover) is answered by eng D17 (one foreground retry).

#### Failure modes registry

```
CODEPATH                 | FAILURE MODE                         | RESCUED? | TEST? | USER SEES?                 | LOGGED?
-------------------------|--------------------------------------|----------|-------|----------------------------|--------
boot unwrap              | key store down                       | Y (exit) | Y     | node down, canary alert    | Y
boot unwrap              | plaintext still present (F1)         | Y        | Y     | refuses, names the file    | Y
boot unwrap              | wrong key (check mismatch)           | Y        | Y     | refuses                    | Y
cluster create Wrap      | key store unavailable                | Y        | Y     | one retry, then 503 key_store_unavailable | Y   (eng D17)
cluster create Wrap      | throttled                            | Y        | Y     | slower, or 503 + Retry-After | Y
failover open            | stale/retired version                | N        | Y     | 503 key_version_retired + alert | Y
re-check                 | revoke signal x N                    | Y        | Y     | full stop, 503 key_revoked | Y
re-check                 | Vault 403 (token expired)            | Y        | Y     | canary alert; no revoke    | Y
revoke                   | egress gateway down                  | Y        | Y     | gateway self-drops after bound | Y
revoke                   | OLD egress gateway ignores clear op  | Y        | Y     | gateway restarted; alert says so | Y   (was a CRITICAL GAP; closed by eng D4)
revoke                   | direct {id}.{domain} route           | by design| Y     | route keeps working (named exception, D10) | n/a
sweep                    | CAS lost                             | Y        | Y     | nothing (correct)          | Y
sweep                    | key store errors                     | Y        | Y     | stale gauge stays > 0      | Y
pkcs11                   | vendor library crash                 | Y        | Y     | helper restarts; brief 503 key_store_unavailable | Y   (eng D5)
pkcs11                   | HSM HA failover                      | Y        | Y     | nothing                    | Y
local -> external switch | rolling-switch window                | Y        | Y     | nothing: two-step switch, no window | Y (eng D8)
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
   -> step 1: add vault/pkcs11 settings to every node (no behaviour change; every node can now open new rows)
   -> step 2: flip SB_SECRET_PROVIDER in a rolling restart (no failover window, eng D8)
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
- [ ] **T4 (P1, human: ~2w / CC: ~1d)** — Phase 3 — `pkcs11` wrapper in the `--pkcs11-helper` process (eng D5).
  - Surfaced by: Design §2; Section 3 (S4).
  - Covers: session pool; re-login; label rules; hardware-slot rule. Decide
    (process: eng D5; package: eng D6).
  - Files: `pkg/secrets/pkcs11/`, `cmd/sandboxd/main.go` (helper entry).
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
    `cmd/sandboxd/main.go`, `cmd/sandboxd/key.go`, `internal/service/key_custody.go`,
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
  - Files: `internal/service/key_custody.go` (adds the sweep cadence to the
    one loop, eng D2), `internal/store/store.go` and a `pkg/secrets` envelope
    comparison helper (eng D3).
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
- [x] **T9 (P2, human: ~1h / CC: ~10min)** — Phase 7 — the enterprise flip
  one release later (F2). Built 2026-10-31 on `feat/key-custody-7-enterprise-refuses-file`,
  the top of the stack, and held: it merges one release after the rest ships.
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

## Eng review (2026-10-21 to 2026-10-30)

Target: `plans/customer-key-custody.md` (this file), PR #784. Binding input:
the CEO review decisions D1–D18 above and `docs/designs/customer-key-custody.md`.
Report file: this file.

### Scope Challenge A: assessment

**Reuse.** Every sub-problem maps to existing code (CEO "What already exists"
table); nothing is rebuilt.

**Complexity.** About 40 changed files [estimated]. New parts:

- the vault wrapper;
- the pkcs11 wrapper and its session pool;
- `limitedWrapper`;
- the custody file and boot decision;
- the revocable AEAD;
- the re-check loop;
- the sweep;
- the `sandboxd key` CLI;
- one gateway op.

That is 8+ files and 2+ new services, so the complexity gate trips. No
feature cuts are proposed: D1–D18 are binding.

**Search check.**

- [Layer 1] Root-key wrapping by a KMS or HSM is how Vault itself stores its
  root key, and in-process PKCS#11 is the common Go practice (crypto11 users,
  Vault's own HSM seal).
- [Layer 2] Vault issue #29532 reports that Transit `rewrap` fails for
  ciphertext encrypted with `associated_data`. The rewrap API lists no AAD
  parameter; decrypt does.
- [Layer 2] CloudHSM SDK 5 and newer HSM libraries need an explicit re-login
  after a reconnect, which matches §2's re-login rule.

**TODOS cross-reference.**

- "A partitioned node keeps serving: /health ignores cluster membership"
  explains why degraded health does not stop ingress routing (§10 already
  says so).
- "A resealed secret whose replacement holder is dead never re-seals" is
  untouched by this plan.
- Nothing in TODOS.md blocks the plan.

**Distribution.** No new binary. `sandboxd` gains a cgo dependency
(`miekg/pkcs11`); the release matrix cross-compiles `sandboxd` with `CC` for
each Linux target (`.github/workflows/release.yml:225-237`). Phase 3 must
prove every matrix target still builds.

**Findings.**

1. **[P1] (confidence: 9/10) `internal/store/store.go:5865-5870`: a rewrapped
   row conflicts with peers' copies forever.** The quoted code:
   `if existingGen.Int64 == rec.SealGeneration { if bytes.Equal(existingPayload,
   rec.SealedPayload) { … } else { return …ErrClusterSecretPayloadConflict`.
   The put-outbox resends the row's current bytes from `cluster_secrets`. Once
   the sweep rewraps the owner's row (same generation, new `WrappedKey`), a
   retried fan-out to a peer that already holds the old bytes gets a payload
   conflict and a non-2xx, so the outbox never drains. That turns CEO-E4b into
   a real defect. Decision: E4b below.
2. **[P2] (confidence: 8/10) §11 and the permissions table: the Vault sweep
   cannot use `rewrap`** (Layer 2 above). This is a factual correction and
   needs no question: §11 uses the plan's own fallback (decrypt, then encrypt
   inside sandboxd), the Vault grant drops `rewrap`, and the Phase 0 rewrap row
   is answered "no". The DEK passes through sandboxd memory during a sweep, as
   it does on every open.
3. **[P2] (confidence: 9/10) `internal/egress/server.go:278`
   (`return nil, fmt.Errorf("unknown op %q", req.Op)`): an old gateway is
   detectable.** This informs CEO-E2e.
4. **[P3] (confidence: 8/10) distribution:** the Phase 3 PR must run the
   release build matrix with the new cgo dependency. This is required proof for
   CEO-1 and needs no question.

**Reality rows (eng).**

| Premise | Claim | Receipt | Verdict |
|---|---|---|---|
| Rewrap conflicts with peer copies | same generation + different bytes is rejected | `internal/store/store.go:5865-5870` | verified (static read) |
| Old gateway detectable | unknown op returns an error | `internal/egress/server.go:278` | verified (static read) |
| Vault rewrap and AAD | rewrap takes no `associated_data` | Vault Transit API docs; vault issue #29532 | verified (docs + issue) |
| `pkg/secrets` only in sandboxd | `cmd/aerolvm`, `cmd/toolboxd`, gatewayd do not import it | `go list -deps` (CEO Section 1) | verified (command) |
| Vault decrypt rejects a wrong AAD | decrypt authenticates `associated_data` | none | unverified (Phase 0) |
| miekg/pkcs11 uses `dlopen` | runtime load | none | unverified |
| Vault Agent proxy injects the token | `use_auto_auth_token` | none | unverified |

unverified=3

```
REALITY: premise-table finding unverified=3; rewrap/peer-copy conflict found plans/customer-key-custody.md:944
REALITY: already-done pass no commits on origin/main since 2026-10-20 touch pkg/secrets, internal/store/store.go or internal/egress internal/store/store.go:5865
REALITY: surface-check pass existing commands verified (sandboxd egress-gateway, aerolvm audit verify); sandboxd key and --key-custody are new internal/egress/gatewayd/run.go:21
REALITY: binding-decisions pass CEO D1-D18 binding; no default reintroduced docs/designs/customer-key-custody.md:22
REALITY: numbers pass all latency/throughput figures deferred to Phase 0; limiter and fleet numbers tagged [estimated] plans/customer-key-custody.md:518
REALITY: deferred-asks pass no linked issue plans/customer-key-custody.md:7
REALITY: pr-count pass 9 stacked PRs (Phases 0,1,2,3,4,4b,5,6 + Phase 7 next release); no ship-policy.json; no partial merges plans/customer-key-custody.md:944
```

### Scope Challenge B: scope record

feature answers: none proposed (CEO D1–D18 binding); structure: Smaller
arrangement (D2, 2026-10-21); accepted scope: all CEO-approved features
unchanged, with one `internal/service/key_custody.go` loop owning re-check,
revoke, recover and the sweep (two cadences, shared background budget), and
the `sandboxd key` CLI in `cmd/sandboxd/key.go` (no new package); pending
remedies: E1, E2, E3, E4, E4b, E5, E6, E7, E8, E9, CEO-E2a, CEO-E2b,
CEO-E2c, CEO-E2e, CEO-E4a.

Scope Challenge result: scope accepted as-is (a smaller arrangement that keeps
scope is not a reduction).

### Section 1: Architecture

Findings (most severe first):

1. [P1] (confidence: 9/10) `internal/egress/server.go:278` and
   `internal/egress/gatewayd/daemon.go:151`: an egress gateway still running the
   old binary after an upgrade keeps the inspection CA key through a revoke
   (the CEO critical gap). Decision: CEO-E2e.
2. [P2] (confidence: 8/10) §2 / Phase 1: one key-store client per process.
   PKCS#11 `C_Initialize` must run once per process (a second call returns
   `CKR_CRYPTOKI_ALREADY_INITIALIZED`). The boot unwrap builds the wrapper
   before `NewCipher` (`pkg/daemon/daemon.go:152-158`), and
   `ConfigureSecretProvider` runs later (`:314`). Phase 1's seam split already
   passes one wrapper into `NewProvider`; the plan now says that one instance
   serves boot, the provider, the loop and the CLI. This is required for
   CEO-1 and needs no question.
3. Open eng choices owned here: E6, E7, CEO-E2b, E9, E4, E1, E2, CEO-E2a.

Section 1 dispositions: finding 1 approved A (D4, CEO-E2e); finding 2
required work, no question (one wrapper instance per process); finding 3:
E6 approved B (D5), E7 approved A (D6), CEO-E2b approved A (D7), E9 approved A
(D8), E4 approved A (D9), E1 approved A (D10), E2 approved A (D11), CEO-E2a
approved A (D12).

### Section 2: Code quality

Findings (most severe first):

1. [P3] (confidence: 8/10) Design §5 / Phase 1: which limiter numbers become
   settings (E5). The plan names `SB_SECRET_PROVIDER_MAX_INFLIGHT` (default 8),
   1 reserved create slot and 2 background slots; HSM partitions differ in
   session limits by vendor. Decision: E5.
2. [P3] (confidence: 9/10) `pkg/secrets/wrap_key_loader.go:72`
   (`if mode&0o077 != 0 {`): the CEO review proposed one shared file-mode
   helper for the upstream wrap key, the PKCS#11 PIN file and the wrapped
   server-key file. Callers: one existing (`LoadUpstreamWrapKeyRing`), two
   proposed (PIN file in Phase 3, wrapped file in Phase 4). Decision: E10.
3. Accuracy of touched diagrams: the CEO Section 1 architecture diagram
   showed a separate "rewrap sweep" box and no PKCS#11 helper; refreshed here
   after D2 and D5 (no question: it records approved answers).

Section 2 dispositions: finding 1 approved A (D13, E5); finding 2 approved
A (D14, E10); finding 3 recorded (diagram refreshed, no question).

### Section 3: Tests

Framework: Go `testing` with table-driven tests (CLAUDE.md "Testing &
coverage"; `make test` is offline; live checks behind the `integration` tag).
Existing tests read for this section: `pkg/secrets/awskms_test.go`
(`TestMapAWSKMSError`), `pkg/secrets/wrap_key_loader_test.go`,
`pkg/secrets/provider_contract_test.go`, `internal/store/cluster_secret_put_outbox_test.go`,
`pkg/api/apihttp/classify_test.go`, `internal/config/config_test.go`.

```
CODE PATHS                                              USER / OPERATOR FLOWS
[+] pkg/secrets                                         [+] Adopt Vault on an existing cluster
  ├── vault wrapper (Wrap/Unwrap/keys)                    ├── [GAP] [→E2E] two-step switch, failover before/after
  │   ├── [GAP] happy, 403+reload, 429, 5xx, bad JSON     │         sweep (cluster-3-mixed-secrets-vault)
  │   └── [GAP] correlation header, AAD mismatch          └── [GAP] [→E2E] custody wrap on a running cluster
  ├── pkcs11 client + helper (eng D5)                   [+] Revoke and recover
  │   ├── [GAP] wrap/unwrap via helper, label rules       ├── [GAP] [→E2E] KMS disable → full stop in bound
  │   ├── [GAP] helper exits mid-call → Unavailable       ├── [GAP] [→E2E] Vault 403 alone never revokes
  │   └── [GAP] re-login after reopen, HW-slot rule       └── [GAP] [→E2E] re-enable → auto-recover (eng D12)
  ├── limitedWrapper                                    [+] Rotate and retire
  │   └── [GAP] cap, reserved create slot, bg budget,     └── [GAP] [→E2E] rotate → gauge 0 → retire → failover
  │             deadline, backoff                       [+] Error states the operator sees
  ├── tags + untagged order (D9)                          ├── [GAP] 503 codes per class (CEO-A1)
  │   └── [GAP] table: local, KMS, mixed, other-tag       ├── [GAP] boot refusals name the file (F1, S5)
  ├── custody file + boot decision (pure fn)              └── [GAP] custody report per config (CEO-E1)
  │   └── [GAP] table over custody × files × cluster ×  [+] Install paths
  │             state.db × seed                           ├── [GAP] [→E2E] cluster-init/join --key-custody
  ├── revocable Cipher                                    └── [GAP] [→E2E] Terraform key_custody variable
  │   └── [GAP] revoke vs in-flight Decrypt, recover
  ├── envelope comparison helper (D3)                   EXISTING (regression risk, see R-REG)
  │   └── [GAP] same content / payload differs           ├── [★★★ TESTED] awskms mapping — awskms_test.go:56
  └── refuseGroupOtherBits (D14)                          ├── [★★★ TESTED] upstream key mode — wrap_key_loader_test.go:82
      └── [GAP] table over modes                          ├── [★★  TESTED] put-outbox conflict — cluster_secret_put_outbox_test.go
[+] internal/service/key_custody.go (eng D2)              ├── [★★  TESTED] provider contract — provider_contract_test.go:17
  ├── [GAP] re-check classifier, N-consecutive, reset     └── [★★  TESTED] error classify — classify_test.go
  ├── [GAP] revoke actions (CA clear, old gateway
  │         restart D4, sessions, health, audit event)
  ├── [GAP] recover (D12)
  └── [GAP] sweep CAS vs 5 writers, local→external
[+] internal/store PutClusterSecret (D3)
  └── [GAP] same gen rewrapped → idempotent
[+] pkg/api/apihttp classify (CEO-A1)
  └── [GAP] five 503 codes, Retry-After

COVERAGE (new paths): 0/31 tested today (all proposed) | existing at-risk paths: 5/5 have tests
QUALITY of existing: ★★★:2 ★★:3 | GAPS: 31 (11 E2E, 0 eval)
```

Every GAP above already has a matching test in the plan's Testing section,
added by the CEO review or this review's decisions; this diagram adds no new
test scope. No LLM or prompt paths, so no eval.

**Value cards (critical paths):**
- Value: protects=a revoked node serves nothing within the bound; fails_when=a revoke signal is mis-classified or the Cipher keeps its AEAD; why_new=no revoke exists today; seam=injectable clock and fake wrapper; no_claim=real KMS/Vault timing (fakes in unit, shortened interval in the live UC)
- Value: protects=a Vault 403 never revokes; fails_when=403 maps to ErrKeyRevoked; why_new=new classifier; seam=none; no_claim=Vault Agent token renewal (faked by removing the token file)
- Value: protects=rewrapped rows do not jam peers; fails_when=PutClusterSecret compares raw bytes again; why_new=put-outbox tests cover payload conflict only; seam=none; no_claim=none beyond protects
- Value: protects=no plaintext key on a wrapped node; fails_when=any of the five locations keeps the key; why_new=no custody mode exists; seam=none; no_claim=disk forensics (checks files and env, not freed blocks)
- Value: protects=helper crash does not take down sandboxd; fails_when=the supervisor stops restarting or calls hang; why_new=no helper exists; seam=helper binary flag; no_claim=real vendor library crash modes (killed process stands in)

**Tests made obsolete:** none. `coverage96_gen_test.go` / `coverage97_test.go`
in `pkg/secrets` and `internal/config` are coverage-named files the CEO review
flagged as patterns to avoid; this plan adds no such files and retires none
(out of scope; a `/test-audit` candidate).

**Regression rule.** Five existing behaviors are at risk from approved
changes. Their coverage contract is decided in R-REG below.

Section 3 dispositions: regression contract approved A (D15, R-REG); E3
approved A (D16); coverage diagram adds no new test scope beyond approved
decisions.

### Section 4: Performance

Findings (most severe first):

1. [P2] (confidence: 7/10) CEO Section 1 production-failure table ("Vault:
   active-node failover returns 503 for seconds ... Gap: no short retry"):
   creates with secrets fail fast during a Vault leader change. Decision: E8.
2. [P3] (confidence: 8/10) Design §10 "Re-check ... default 5 minutes", "N
   default 3": the defaults set the revoke bound in the claim (~15 min) and
   the fleet's steady key-store load (~7 calls/s at 2,000 nodes
   [estimated]). Decision: CEO-E2c.
3. [P3] (confidence: 8/10) Design §11 "It runs at boot and then on a cadence
   (CEO-E4a)": the cadence decides how long an operator waits for the stale
   gauge to reach 0 before retiring a version. Decision: CEO-E4a.
4. [P3] (confidence: 6/10, medium confidence, verify) eng D5 adds an IPC hop
   per PKCS#11 call (about 0.1 ms [estimated]) against an HSM round trip of
   milliseconds; no action beyond Phase 0 measuring it with the rest.
5. Memory, queries and indexes: unchanged from CEO Section 7 (paged sweep, no
   new index, no cache). No issues found.

Section 4 dispositions: finding 1 approved A (D17, E8); finding 2 approved
A (D18, CEO-E2c); finding 3 approved A (D19, CEO-E4a); findings 4 and 5
recorded, no action.

### Outside voice (codex, eng phase)

Codex completed (model gpt-6-astra via the gstack catalog; full output in
the review conversation). Seven findings; each was checked against the code
before acting:

| # | Severity | Finding | Verified? | Disposition |
|---|---|---|---|---|
| OV1 | High | D3 keeps incoming bytes, so a delayed pre-sweep copy can overwrite a rewrapped row after its gauge read 0 | yes: D3 accepted scope ("the incoming bytes are kept") | decision OV1 (reopens D3) |
| OV2 | High | clearing the CA leaves established inspected connections running and injection secrets in the gateway | yes: `serveInspect` loads the inspector once per connection (`internal/egress/proxy/inspect.go:108-110`); inject rules read `cur.Spec.Secrets` (`:251`); secrets are memory-only (`internal/egress/snapshot.go:34`) | decision OV2 |
| OV3 | High | the two-step switch fails for `local → awskms`: AWS rows are untagged and the AWS fallback requires the provider to be `awskms` | yes: §12 "if that fails and the provider is `awskms`" | decision OV3 (reopens D9 wording) |
| OV4 | High | PKCS#11 label rotation has no cluster rollout order; "0 stale" does not prove every node targets the same label | yes: labels are per-node settings (§2) | decision OV4 |
| OV5 | High | backups archive `/etc/sandboxd`, including `cluster.env` with the plaintext key, so old backups still decrypt after wrapping | yes: `scripts/sandboxd-backup.sh:69` (`copy_if_exists "$config_dir" ...`) | decision OV5 |
| OV6 | Medium | the PKCS#11 helper is restarted on exit but not on a hang | yes: §2 (eng D5) covers exits only | decision OV6 |
| OV7 | Medium | `openRawEnvelope` turns unwrap errors other than three provider classes into `ErrDecryptFailed` with `%v`, so `ErrKeyRevoked` and `ErrKeyVersionRetired` never reach the 503 mapping | yes: `pkg/secrets/envelope.go:255-260` | **applied, no question**: necessary implementation of approved CEO-A1 and CEO-E2; both new sentinels pass through, and a provider-to-handler test checks the 503 code |

Outside voice dispositions: OV1 approved A (D20, reopened D3); OV2 approved
A (D21); OV3 approved A (D22, reopened D9 wording); OV4 approved A (D23); OV5
approved A (D24); OV6 approved A (D25); OV7 applied as required work. No
remaining disagreement with the outside voice.

## Decision ledger (eng review)

### E4b: rewrapped rows vs peer copies
Finding: Scope Challenge 1, P1, confidence 9/10, `internal/store/store.go:5865-5870`, reviewer: eng review (Claude)
Plan baseline: CEO-E4b open ("confirm nothing compares sealed bytes across nodes"), gate row blocks Phase 4b
Runtime evidence: `PutClusterSecret` rejects same `seal_generation` with different `sealed_payload` as `ErrClusterSecretPayloadConflict` (static read); the put-outbox resends the row's current bytes
Comparison grid:

```text
Commitment                          | Current                   | A (compare without key)        | B (sweep skips outbox rows)     | C (both)
same gen, only WrappedKey differs   | conflict, non-2xx forever | idempotent; keep incoming bytes| still conflict (never sent)     | idempotent
same gen, payload differs           | conflict                  | conflict (unchanged)           | conflict                        | conflict
rows with a pending outbox          | n/a                       | rewrapped normally             | skipped until outbox drains     | skipped
retirement after a dead peer        | n/a                       | not blocked                    | blocked until the outbox retires| blocked
where the fix lives                 | n/a                       | one shared comparison in store | sweep only                      | both
effort                              | n/a                       | S (human ~1d / CC ~30min)      | S (human ~1d / CC ~30min)       | S+S
```

Question D3:
D3 — E4b: After the sweep rewraps a row, how do peers accept the new copy without a "payload conflict"?
Project: plans/customer-key-custody on PR #784; Scope Challenge finding 1 (P1, confidence 9/10).
ELI10: When a node re-wraps a secret's key onto the newest key version, the secret itself does not change, only the small wrapped key inside it. But peers check "same version, different bytes" and reject that as a conflict (internal/store/store.go:5865-5870). If the owner later resends that row to a peer, the peer refuses forever and the retry queue never drains.
Stakes if we pick wrong: the retry queue jams after the first key rotation, and a dead peer could block key retirement indefinitely.
Recommendation: A because the comparison every caller goes through is the root cause, so fixing it once covers the sweep and any future rewrap (fix it once where they all route through).
Note: options differ in kind, not coverage — no completeness score.
Net: fix the shared check once, against keeping rewrapped bytes off the wire at the cost of blocked retirements.
Header: Rewrap conflict
Options:
A) Compare without the key
The peer-copy check treats same generation and same envelope apart from `WrappedKey` as idempotent and keeps the incoming bytes, so peers converge on the newest wrapping; a different payload is still a conflict. Effort S (human ~1d / CC ~30min), risk low; one shared helper in `pkg/secrets`. ✅ Fixes the root cause in the one comparison every peer write goes through. ✅ Rotation and retirement never wait on a slow or dead peer. ❌ The store now parses the envelope instead of comparing raw bytes.
B) Sweep skips outbox rows
The sweep leaves any row with a pending put or delete outbox entry alone, so rewrapped bytes are never resent. Effort S (human ~1d / CC ~30min), risk medium. ✅ No change to the peer receive path. ✅ Very small diff. ❌ A dead peer keeps its outbox row for a long time, so that sandbox's key can never be retired.
C) Both
Do A and also skip rows with a pending outbox. Effort S+S, risk low. ✅ Belt and braces against any other byte comparison. ✅ Rewrapped bytes rarely travel at all. ❌ Inherits B's retirement block for rows behind a dead peer.

State: approved
Actual answer: A) Compare without the key (D3, 2026-10-21)
Accepted scope: a `pkg/secrets` helper that compares two sealed envelopes on every field except `WrappedKey`; `PutClusterSecret` uses it at `internal/store/store.go:5865` and `:5888`, so same generation and same content is idempotent and the incoming bytes are kept, while a different payload stays a conflict; a store test for both cases; §11, Phase 4b and the gate table updated.
History: the "incoming bytes are kept" half was reopened by outside voice OV1 and replaced by D20 (keep the bytes already on disk); the comparison itself stands.

### CEO-E2e: old egress gateway after an upgrade
Finding: Section 1 finding 1, P1, confidence 9/10, `internal/egress/server.go:278`, reviewer: eng review (Claude)
Plan baseline: open (gate table, blocks Phase 4); CEO failure-modes registry marks it the one CRITICAL GAP
Runtime evidence: the gateway keeps the CA in memory only and "sandboxd sends it again after every gateway start" (`internal/egress/gatewayd/daemon.go:147-151`); an unknown op returns `unknown op %q` (`internal/egress/server.go:278`); the gateway is designed to outlive sandboxd restarts
Comparison grid:

```text
Commitment                         | Current         | A (restart on unknown op)            | B (restart old gateway at upgrade) | C (alert only)
revoke with an old gateway         | CA stays (silent)| sandboxd restarts the gateway unit; | gateway already new at revoke time | alert; CA stays until an operator
                                   |                 | it comes up without the CA          |                                    | restarts the gateway
egress blip                        | none            | only on that rare revoke            | at every upgrade with an old gateway| none
gateway outlives sandboxd restarts | yes (by design) | kept                                | broken for upgrades                | kept
critical gap closed                | no              | yes                                 | yes                                | no (visible, not closed)
effort                             | n/a             | S (human ~1d / CC ~30min)           | S-M (human ~2d / CC ~1h)           | S
```

Question D4:
D4 — CEO-E2e: When a key is revoked but the node's egress gateway is still an old version that does not understand "clear the CA", what does sandboxd do?
Project: plans/customer-key-custody on PR #784; Section 1 finding 1 (P1, the CEO review's one critical gap).
ELI10: The egress gateway is a separate long-running program that holds the private key it uses to inspect sandboxes' HTTPS traffic. It is designed to keep running across sandboxd upgrades, so right after an upgrade it may be the old version. On a revoke, sandboxd sends it a new "clear the CA" message; an old gateway answers "unknown op" and keeps the key, silently. The gateway only holds the key in memory, so restarting it clears the key for good.
Stakes if we pick wrong: a revoke that looks complete while one process still holds a customer-derived key.
Recommendation: A because it closes the gap with a restart only in the rare revoke-plus-old-gateway case, and keeps the gateway's designed ability to outlive normal upgrades.
Note: options differ in kind, not coverage — no completeness score.
Net: a targeted restart on a revoke, against restarting gateways at every upgrade or leaving the gap visible but open.
Header: Old gateway
Options:
A) Restart on unknown op
If the gateway answers `unknown op` to `clear_inspect_ca`, sandboxd restarts the gateway's systemd unit; the gateway comes back without the CA (it is memory-only) and a revoked sandboxd never resends it. The revoke alert says the gateway was restarted. Effort S (human ~1d / CC ~30min), risk low; tested with a fake old gateway. ✅ Closes the critical gap in every version mix. ✅ Normal upgrades still leave the gateway running. ❌ That one revoke briefly interrupts all egress on the node while the gateway restarts.
B) Restart at upgrade
At sandboxd startup, check the gateway's supported ops; if it is too old, restart it right away, so an old gateway never meets a revoke. Effort S-M (human ~2d / CC ~1h), risk medium. ✅ Never relies on the revoke moment. ✅ Old gateways disappear quickly after any upgrade. ❌ Every upgrade with an old gateway now blips egress, which the gateway was designed to avoid.
C) Alert only
Raise an alert that the revoke is incomplete until the gateway is restarted by hand. Effort S, risk medium. ✅ No automatic restarts at all. ✅ Smallest change. ❌ The CA stays in memory until a human acts, so the gap is visible but still open.

State: approved
Actual answer: A) Restart on unknown op (D4, 2026-10-21; asked twice at the user's request, same answer both times)
Accepted scope: on revoke, if the gateway answers `unknown op` to `clear_inspect_ca`, sandboxd restarts `aerolvm-egress-gateway.service`; the gateway comes back without the CA (memory-only) and a revoked sandboxd never resends it; the `SandboxdKeyRevoked` alert and the `key_revoked` audit event note the restart; a test with a fake old gateway; §10, Phase 4 and the failure-modes registry updated (critical gap closed).
History: none

### E6: PKCS#11 in-process or in a helper process
Finding: Section 1 finding 3, P2, confidence 8/10, Design §2 ("Library. Use `github.com/miekg/pkcs11`"), reviewer: eng review (Claude)
Plan baseline: open (gate table, blocks Phase 3); CEO Section 3 S4 (vendor library inside sandboxd: Low likelihood, High impact)
Runtime evidence: sandboxd already runs code out of process with the same binary (`--wasm-worker`, `--wasm-resident-host`, `cmd/sandboxd/main.go:39`, `:63`); Vault's own HSM seal and crypto11 users load PKCS#11 in-process [Layer 1]
Comparison grid:

```text
Commitment                         | Current (plan)       | A (in-process)                   | B (helper process)
where the vendor library runs      | sandboxd process     | sandboxd process                 | `sandboxd --pkcs11-helper`, UDS 0600
vendor crash                       | sandboxd dies        | sandboxd dies; systemd restarts  | helper dies; sandboxd restarts it; callers
                                   |                      |                                  | see Unavailable for a moment
vendor bug reading memory          | can read everything  | can read everything              | sees only the DEKs it wraps
latency per call                   | HSM round trip       | HSM round trip                   | + ~0.1 ms IPC [estimated]
follow-up TODO for a helper        | none                 | asked separately at TODO stage   | n/a
effort                             | M                    | M (human ~1w / CC ~4h)           | L (human ~2w / CC ~1d)
```

Question D5:
D5 — E6: Should the vendor's HSM library run inside sandboxd, or in a small separate helper process?
Project: plans/customer-key-custody on PR #784; Section 1 finding 3 (P2).
ELI10: Talking to an HSM means loading the vendor's C library into a program. Inside sandboxd, a crash or memory bug in that library takes down the whole daemon and could read everything sandboxd holds in memory. In a small helper process, only the helper crashes and it only ever sees the keys it wraps. sandboxd already runs its WASM workers this way, so the pattern exists. It costs about a week more.
Stakes if we pick wrong: in-process means a vendor library bug can crash every sandbox's control plane on that node; a helper adds a moving part to build and test.
Recommendation: A because it is how Vault itself and most Go HSM users load PKCS#11 (boring by default), and a vendor crash only costs a systemd restart.
Note: options differ in kind, not coverage — no completeness score.
Net: the proven, simpler in-process path, against isolating vendor code at about a week's extra cost.
Header: HSM process
Options:
A) In-process (recommended)
Load the vendor library in sandboxd through `miekg/pkcs11`, as the plan says. A vendor crash restarts sandboxd under systemd. Effort M (human ~1w / CC ~4h), risk medium. ✅ The common, proven pattern, with nothing new to supervise. ✅ No IPC hop on every wrap and unwrap. ❌ A vendor library crash or memory bug affects the whole daemon.
B) Helper process
Run `sandboxd --pkcs11-helper` (same binary, like the WASM worker) behind a 0600 Unix socket with Wrap, Unwrap and Ping; sandboxd restarts it on exit. Effort L (human ~2w / CC ~1d), risk medium. ✅ A vendor crash costs a helper restart, not the daemon. ✅ Vendor code never sees sandboxd's memory. ❌ A new process, protocol and supervisor to build, test and keep version-matched.

State: approved
Actual answer: B) Helper process (D5, 2026-10-21; against the in-process recommendation)
Accepted scope: the vendor library runs only in `sandboxd --pkcs11-helper` (same binary), started and supervised by sandboxd behind a 0600 Unix socket in `/run/sandboxd`, with Wrap, Unwrap, Ping and Info ops; the session pool, login and `C_Initialize` live in the helper; sandboxd restarts it on exit with backoff and callers see `ErrProviderUnavailable` meanwhile; §2, Section 3 S4, Phase 3 (now L), tests and the failure-modes registry updated.
History: an earlier draft had a third option that bundled a follow-up TODO; removed so the TODO is asked on its own.

### E7: where the PKCS#11 code lives
Finding: Section 1 finding 3, P3, confidence 8/10, Design §5 code quality ("PKCS#11 in its own package (E7)"), reviewer: eng review (Claude)
Plan baseline: open (gate table, blocks Phase 3); eng D5 put the vendor library in a helper process
Runtime evidence: `pkg/secrets` is linked only into sandboxd, which is already cgo (`go list -deps`, CEO Section 1); `pkg/wasm` keeps its optional engine behind a build tag (CLAUDE.md repository map)
Comparison grid:

```text
Commitment                    | Current     | A (own package)                                   | B (inside pkg/secrets)
package                       | undecided   | `pkg/secrets/pkcs11` (cgo), helper main in        | files in `pkg/secrets`, helper main in
                              |             | `cmd/sandboxd`                                    | `cmd/sandboxd`
non-cgo build of pkg/secrets  | n/a         | still builds; pkcs11 package has a `!cgo` stub     | needs cgo for the whole package
                              |             | that returns "pkcs11 needs a cgo build"           |
test isolation                | n/a         | fake-p11 tests in their own package               | mixed into the 3,800-line package tests
helper process (eng D5)       | approved    | unchanged                                         | unchanged
effort                        | n/a         | S (human ~2h / CC ~15min)                         | S (none extra)
```

Question D6:
D6 — E7: Should the HSM code live in its own Go package, or inside the existing secrets package?
Project: plans/customer-key-custody on PR #784; Section 1 finding 3 (P3); D5 already put the vendor library in a helper process.
ELI10: The HSM code needs C bindings (cgo). If it sits inside the main secrets package, every program that imports that package must be built with cgo too. A separate small package keeps the C part fenced off, gives it its own tests, and lets a non-cgo build fail with a clear "needs cgo" message instead of a compile error.
Stakes if we pick wrong: mixing it in makes the secrets package harder to build and test on its own; splitting it adds one package to wire up.
Recommendation: A because it keeps cgo and the vendor binding out of the package every other piece of sandboxd depends on, at almost no cost (explicit over clever).
Note: options differ in kind, not coverage — no completeness score.
Net: a fenced-off C binding, against one fewer package.
Header: HSM package
Options:
A) Own package (recommended)
Put the PKCS#11 code in `pkg/secrets/pkcs11` with a `!cgo` stub, wired by `pkg/daemon` and the helper's entry point in `cmd/sandboxd`. Effort S (human ~2h / CC ~15min), risk low. ✅ `pkg/secrets` stays pure Go and builds without cgo. ✅ The vendor binding and its fakes are tested on their own. ❌ One more package and import to wire through the factory.
B) Inside pkg/secrets
Add the PKCS#11 files to `pkg/secrets` next to `awskms.go`. Effort S (nothing extra), risk low. ✅ Every wrapper lives side by side in one place. ✅ No extra wiring. ❌ The whole secrets package then needs cgo to build, including for its unit tests.

State: approved
Actual answer: A) Own package (D6, 2026-10-21)
Accepted scope: PKCS#11 code in `pkg/secrets/pkcs11` (cgo) with a `!cgo` stub returning "pkcs11 needs a cgo build"; wired by `pkg/daemon` and the helper entry point in `cmd/sandboxd`; §5, the gate table and T4 updated.
History: none

### CEO-E2b: should a revoked node steer placement away
Finding: Section 1 finding 3, P3, confidence 8/10, Design §10 "Pending for eng review: CEO-E2b", reviewer: eng review (Claude)
Plan baseline: open (gate table, blocks Phase 4; CLAUDE.md rule 6 if yes)
Runtime evidence: every node in a cluster wraps the same server key under the same key-store key (§3 "All cluster nodes share one server key"), so a deliberate revoke trips on every node that can reach the key store within the same bound; a node that cannot reach it never trips (claim text)
Comparison grid:

```text
Commitment                        | Current            | A (no placement change)                  | B (placement skips revoked nodes)
creates routed to a revoked node  | n/a                | fail closed with 503 key_revoked         | routed to a node without the flag
cluster-wide revoke               | all nodes trip     | every node fails closed (same outcome)   | every node flagged; nothing to route to
partial revoke (some nodes only)  | n/a                | only when some nodes cannot reach the    | creates go to nodes that never saw the
                                  |                    | key store; those keep serving anyway     | revoke, which may hold the key longer
internal/cluster change           | none               | none                                     | a gossip capacity flag + placement filter;
                                  |                    |                                          | rule 6 regression test and call-out
effort                            | n/a                | S (nothing extra)                        | M (human ~3d / CC ~3h)
```

Question D7:
D7 — CEO-E2b: When a node has been revoked, should the cluster stop sending it new sandboxes?
Project: plans/customer-key-custody on PR #784; Section 1 finding 3 (P3).
ELI10: A revoked node refuses every request with a clear "key revoked" error. We could also teach the cluster's placement logic to stop picking that node. But every node in a cluster uses the same key, so a real revoke hits all of them within the same window, and there is no healthy node to send work to. The only nodes that would still be picked are ones that cannot reach the key store, which is the opposite of what a revoke wants.
Stakes if we pick wrong: B touches the fragile cluster placement code for a case where it changes nothing or routes work to the wrong node.
Recommendation: A because a revoke is cluster-wide by construction, so placement awareness buys nothing and costs a change in the riskiest part of the repo (blast radius, boring by default).
Note: options differ in kind, not coverage — no completeness score.
Net: no cluster change, against routing around a revoke that has no healthy nodes to route to.
Header: Placement
Options:
A) No placement change (recommended)
A revoked node fails closed with 503 `key_revoked` and degraded health; placement is untouched. Effort S (nothing extra), risk low. ✅ No change to `internal/cluster`, the most fragile area in the repo. ✅ Correct for the real case, where every node revokes together. ❌ A create that lands on a revoked node gets an error instead of being re-routed.
B) Placement skips revoked nodes
Add a "key revoked" flag to the gossip capacity heartbeat and filter it in placement. Effort M (human ~3d / CC ~3h), risk medium; needs a regression test next to `placement.go` and a cluster-correctness call-out (CLAUDE.md rule 6). ✅ Creates avoid a node that cannot serve them. ✅ Useful if a future design ever revokes one node alone. ❌ In a real revoke it either finds no node, or picks one that has not yet seen the revoke.

State: approved
Actual answer: A) No placement change (D7, 2026-10-21)
Accepted scope: no change to `internal/cluster`; a revoked node fails closed with 503 `key_revoked` and degraded health; §10, the coordination note and the gate table updated.
History: none

### E9: the rolling-switch window
Finding: Section 1 finding 3, P2, confidence 8/10, Design §12 "Known limit, rolling switch", reviewer: eng review (Claude)
Plan baseline: CEO-M1 (D15) accepted local → external migration with a documented window; E9 open (blocks Phase 4b)
Runtime evidence: provider tags (§4) let `Unwrap` dispatch by tag before calling out, so a node can tell a `vault:` or `p11:` row from a local one without being configured to seal with that provider
Comparison grid:

```text
Commitment                         | Current (D15)                 | A (two-step switch)                         | B (accept the window)
unswitched node meets a vault row  | cannot open it                | opens it: it has the vault settings already | cannot open it
what decides how a node opens      | SB_SECRET_PROVIDER only       | the row's tag + whichever backend settings  | SB_SECRET_PROVIDER only
                                   |                               | the node has                                |
what decides how a node seals      | SB_SECRET_PROVIDER            | SB_SECRET_PROVIDER (unchanged)              | SB_SECRET_PROVIDER
runbook                            | one rolling restart           | 1) add backend settings everywhere (no      | one quick rolling restart
                                   |                               | behaviour change) 2) flip the provider      |
failover gap during the switch     | yes, for the restart window   | none                                        | yes, for the restart window
effort                             | n/a                           | S (human ~1d / CC ~30min)                   | S (docs)
```

Question D8:
D8 — E9: During a switch from local to Vault or HSM, how do we avoid sandboxes losing their failover copy for the length of the rolling restart?
Project: plans/customer-key-custody on PR #784; Section 1 finding 3 (P2).
ELI10: Nodes switch one at a time. A node that has switched seals new secrets with Vault, but a node that has not switched yet cannot open them, so a sandbox created in that window has no usable backup copy on the unswitched nodes. Because every wrapped key now says which backend made it, we can let any node open a Vault-made row as long as it has the Vault settings, even before it starts sealing with Vault. The switch then becomes two harmless steps: hand every node the Vault settings, then flip which backend seals.
Stakes if we pick wrong: B leaves a real failover hole every time a customer adopts Vault or an HSM; A adds one rule about how rows are opened.
Recommendation: A because it removes the gap completely with a small rule that the provider tags already make possible (edge cases over speed).
Note: options differ in kind, not coverage — no completeness score.
Net: a gap-free two-step switch, against a documented failover hole.
Header: Switch window
Options:
A) Two-step switch (recommended)
A node opens any tagged row whose backend it has settings for, whatever `SB_SECRET_PROVIDER` says; sealing still follows `SB_SECRET_PROVIDER`. The runbook adds the backend settings to every node first, then flips the provider in a rolling restart. Effort S (human ~1d / CC ~30min), risk low; tested by opening a `vault:` row on a node still sealing local. ✅ No sandbox loses its failover copy at any point in the switch. ✅ Reuses the tags; no new format. ❌ The node now needs key-store access for opening before it seals with it, which the runbook must say.
B) Accept the window
Keep §12 as written: switch config everywhere, then do a quick rolling restart, and document the window. Effort S (docs), risk medium. ✅ Nothing new in the open path. ✅ Simple to explain. ❌ Sandboxes created during the restart window can lack a usable failover copy until every node has switched.

State: approved
Actual answer: A) Two-step switch (D8, 2026-10-25)
Accepted scope: a node opens any tagged row whose backend it has settings for, regardless of `SB_SECRET_PROVIDER`; sealing still follows `SB_SECRET_PROVIDER`; the runbook adds backend settings to every node, then flips the provider in a rolling restart; a test opening a `vault:` row on a node still sealing local; §4, §12, the deployment sequence and the gate table updated.
History: none

### E4: how untagged rows are opened
Finding: Section 1 finding 3, P3, confidence 9/10, Design §4 and §12 ("an untagged row is opened with the server key first, then with AWS KMS"), reviewer: eng review (Claude)
Plan baseline: CEO-M1 (D15) revised E4 from "untagged = awskms" to "local first, then awskms"; open for eng confirmation (blocks Phase 1)
Runtime evidence: a local row's DEK is `Cipher.EncryptWithAAD(dek, KeyAADBound(...))` (`pkg/secrets/envelope.go:130`), an `awskms` row's is an opaque KMS blob; both are untagged bytes today; GCM authenticates the local attempt, so a wrong guess fails cleanly
Comparison grid:

```text
Commitment                        | Current (D15 text)             | A (trial: local, then awskms)      | B (explicit legacy setting)
untagged row on a local node      | server key                     | server key                         | per SB_SECRET_LEGACY_ROWS
untagged row on an awskms node    | server key, then AWS KMS       | server key, then AWS KMS           | per SB_SECRET_LEGACY_ROWS
mixed history (local then awskms) | both open                      | both open                          | only the configured kind opens
cost of a wrong first guess       | one local GCM open (µs)        | one local GCM open (µs)            | none
new setting                       | none                           | none                               | SB_SECRET_LEGACY_ROWS=local|awskms
effort                            | n/a                            | S (as planned)                     | S
```

Question D9:
D9 — E4: For old rows with no provider tag, should a node try the server key first and then AWS KMS, or should an operator setting say which kind they are?
Project: plans/customer-key-custody on PR #784; Section 1 finding 3 (P3).
ELI10: Rows sealed before this change carry no label saying who wrapped them; they are either "local" (wrapped by the server key) or AWS KMS. Trying the server key first costs microseconds and fails cleanly if wrong, because the encryption checks itself; then AWS KMS gets its turn. A setting would skip the guess but breaks clusters whose history has both kinds, for example a cluster that moved from local to AWS KMS.
Stakes if we pick wrong: a setting can leave a mixed-history cluster unable to open half its old rows; the trial costs one cheap local check per old row.
Recommendation: A because it opens every real history correctly with no new setting, and the wrong guess is authenticated and cheap (explicit over clever does not need a knob here).
Note: options differ in kind, not coverage — no completeness score.
Net: a cheap authenticated guess that always works, against a setting that skips the guess but can strand mixed histories.
Header: Untagged rows
Options:
A) Trial: local, then AWS KMS (recommended)
Open an untagged row with the server key and local rules first; if that fails and the provider is `awskms`, try AWS KMS. Effort S (as planned), risk low; table test for each history. ✅ Works for local-only, KMS-only and mixed histories with no configuration. ✅ The failed first try is authenticated and costs microseconds. ❌ An `awskms` node does one wasted local check each time it opens an old untagged row (AWS rows are never swept).
B) Explicit legacy setting
Add `SB_SECRET_LEGACY_ROWS=local|awskms` and open untagged rows only that way. Effort S, risk medium. ✅ No guessing at all. ✅ The operator states the history explicitly. ❌ A cluster whose old rows include both kinds cannot open some of them.

State: approved
Actual answer: A) Trial: local, then AWS KMS (D9, 2026-10-25)
Accepted scope: unchanged design (§4, §12): untagged rows open with the server key first, then AWS KMS when that is the provider; a table test per history (local-only, KMS-only, mixed); gate table and "Decisions needed" E4 marked answered.
History: the "when that is the provider" condition was reopened by outside voice OV3 and replaced by D22 (whenever AWS KMS settings are present); the trial order stands.

### E1: how sandboxd authenticates to Vault
Finding: Section 1 finding 3, P3, confidence 8/10, Design §1 "Auth (v1): no login code in sandboxd", reviewer: eng review (Claude)
Plan baseline: recommended token file + Agent proxy only; open (blocks Phase 2)
Runtime evidence: none in the repo (no Vault code exists); Vault Agent auto-auth supports AppRole, Kubernetes, AWS IAM and TLS cert methods [in-distribution knowledge, unverified]
Comparison grid:

```text
Commitment                     | Current (plan)                   | A (Agent only)                       | B (Agent + direct login)
token file from Vault Agent    | yes                              | yes                                  | yes
Agent API proxy (no token)     | yes                              | yes                                  | yes
direct AppRole/Kubernetes login| no                               | no                                   | yes: login, token renew, re-login on
                                |                                  |                                      | expiry inside sandboxd
secrets held by sandboxd       | token (file) or none (proxy)     | token (file) or none (proxy)         | + role_id/secret_id or SA token path
node dependency                | Vault Agent                      | Vault Agent                          | Vault Agent optional
effort                         | n/a                              | S (as planned)                       | M (human ~4d / CC ~3h)
```

Question D10:
D10 — E1: Should sandboxd log in to Vault itself, or rely on Vault Agent running next to it?
Project: plans/customer-key-custody on PR #784; Section 1 finding 3 (P3).
ELI10: To call Vault, sandboxd needs a token. HashiCorp's own tool, Vault Agent, can log in with any method a customer uses (AppRole, Kubernetes, AWS, certificates), keep the token fresh, and either write it to a file or add it to requests for us. Building login into sandboxd means re-implementing token renewal and every login method we choose to support, and holding the login credential ourselves.
Stakes if we pick wrong: building login now adds secret-handling code that Vault Agent already does well; relying on Agent adds one process customers must run.
Recommendation: A because Vault Agent is HashiCorp's supported way to do this, it covers every login method, and sandboxd then never holds a login credential (boring by default).
Note: options differ in kind, not coverage — no completeness score.
Net: one fewer credential and no renewal code, against one more process customers must run.
Header: Vault auth
Options:
A) Vault Agent only (recommended)
sandboxd reads a token file written by Vault Agent, or sends requests through Agent's local proxy; it has no login code. Effort S (as planned), risk low. ✅ Every Vault login method works through Agent with no code in sandboxd. ✅ In proxy mode sandboxd holds no Vault credential at all. ❌ Customers must run and supervise Vault Agent on each node.
B) Agent plus direct login
Also support AppRole and Kubernetes login inside sandboxd, with token renewal and re-login. Effort M (human ~4d / CC ~3h), risk medium. ✅ Works without Vault Agent for those two methods. ✅ One fewer process on the node. ❌ sandboxd must hold and protect a login credential and own token renewal, which Agent already does.

State: approved
Actual answer: A) Vault Agent only (D10, 2026-10-25)
Accepted scope: unchanged design (§1 Auth): token file written by Vault Agent, or the Agent API proxy; no login code in sandboxd; gate table and "Decisions needed" E1 marked answered.
History: none

### E2: a thin Vault client or HashiCorp's library
Finding: Section 1 finding 3, P3, confidence 8/10, Design §1 "Client. A thin HTTP client in `pkg/secrets/vault.go`", reviewer: eng review (Claude)
Plan baseline: recommended thin client; open (blocks Phase 2)
Runtime evidence: `github.com/hashicorp/vault/api` is not in `go.mod` today (checked); the repo's own thin REST clients are `pkg/caddy/client.go` and `pkg/firecracker/client.go`; the calls needed are two POSTs (encrypt, decrypt) and one GET (`keys/<key>`), after eng D10 removed login
Comparison grid:

```text
Commitment                      | Current (plan)          | A (thin client)                         | B (hashicorp/vault/api)
endpoints used                  | encrypt, decrypt, keys  | encrypt, decrypt, keys                  | same, through the library
new module dependencies         | none                    | none                                    | vault/api and its transitive tree
token file reload, headers      | ours                    | ours (~250 lines with tests)            | library + our wrapper
TLS / CA / namespace            | ours                    | stdlib net/http                         | library config
error mapping table (§1)        | ours                    | ours, on HTTP status + body             | ours, on library error types
effort                          | n/a                     | S (human ~2d / CC ~2h)                  | S (human ~1d / CC ~1h) + dependency review
```

Question D11:
D11 — E2: Should the Vault client be a small hand-written HTTP client, or HashiCorp's official Go library?
Project: plans/customer-key-custody on PR #784; Section 1 finding 3 (P3); after D10 there is no login code, so the client needs three calls.
ELI10: sandboxd only needs to call three Vault endpoints: encrypt, decrypt and read the key's version. A small client in the style of the repo's existing Caddy and Firecracker clients is about 250 lines with no new dependencies. HashiCorp's library saves writing those lines but brings its whole dependency tree into the security-sensitive secrets package, which then has to be reviewed and kept patched.
Stakes if we pick wrong: the library adds dependency and CVE-tracking weight to the most sensitive package; the thin client means we own a little more HTTP code.
Recommendation: A because three calls do not justify a new dependency tree in the secrets package, and the repo already has this exact client pattern twice (reuse before adding a dependency).
Note: options differ in kind, not coverage — no completeness score.
Net: about 250 lines of familiar code, against a new dependency tree in the secrets package.
Header: Vault client
Options:
A) Thin client (recommended)
Write `pkg/secrets/vault.go` on `net/http`, like `pkg/caddy/client.go`, behind a narrow `vaultAPI` interface for tests. Effort S (human ~2d / CC ~2h), risk low. ✅ No new module dependencies in the secrets package. ✅ Same pattern and test style as the repo's other REST clients. ❌ We own the HTTP details (timeouts, keep-alive limits, error bodies) ourselves.
B) HashiCorp's library
Use `github.com/hashicorp/vault/api` for the calls and wrap it in our error mapping. Effort S (human ~1d / CC ~1h) plus a dependency review, risk medium. ✅ HashiCorp maintains the client and its quirks. ✅ Less of our own HTTP code. ❌ A large dependency tree enters the most security-sensitive package and must be tracked for CVEs.

State: approved
Actual answer: A) Thin client (D11, 2026-10-25)
Accepted scope: unchanged design (§1 Client): `pkg/secrets/vault.go` on `net/http` behind a narrow `vaultAPI` interface; no new module dependency; gate table and "Decisions needed" E2 marked answered.
History: none

### CEO-E2a: recovery after the key comes back
Finding: Section 1 finding 3, P2, confidence 8/10, Design §10 "Pending for eng review: CEO-E2a", reviewer: eng review (Claude)
Plan baseline: open (blocks Phase 4); the custody state machine (CEO Section 1) allows REVOKED → ACTIVE only on a fresh unwrap plus a matching check, and only if this answer is "auto-recover"
Runtime evidence: the revocable `Cipher` holds its AEAD behind an atomic pointer, so a swap back is one store (Design §10 "The mechanism"); the gateway takes the CA again through `set_inspect_ca` (`internal/egress/gatewayd/daemon.go:151`)
Comparison grid:

```text
Commitment                       | Current         | A (auto-recover)                              | B (restart only)
when service returns             | undecided       | next re-check after re-enable (<= 5 min)      | when an operator restarts the node
what proves the key is back      | n/a             | a fresh unwrap of the stored file + matching  | the boot unwrap + check
                                 |                 | check                                         |
what is restored                 | n/a             | Cipher AEAD swap, CA re-sent to the gateway,  | everything, by a normal boot
                                 |                 | health back to ok, counter reset              |
evidence                         | n/a             | `key_recovered` audit event (new Kind), alert | boot log + `key_custody_changed` if custody
                                 |                 | resolves                                      | changed
flapping                         | n/a             | a re-revoke needs N revoked results again     | n/a
effort                           | n/a             | S (human ~1d / CC ~1h)                        | S (nothing extra)
```

Question D12:
D12 — CEO-E2a: After a customer revokes and then re-enables their key, should nodes come back on their own or only after a restart?
Project: plans/customer-key-custody on PR #784; Section 1 finding 3 (P2).
ELI10: A revoke makes every node stop processing within about 15 minutes. If the customer then re-enables the key, perhaps because the revoke was a mistake, the nodes can notice on their next 5-minute check that the key works again and switch themselves back on. The alternative is that someone restarts every node by hand. Coming back on its own needs the same proof a boot uses: unwrap the stored key and check it matches.
Stakes if we pick wrong: restart-only turns an accidental revoke into a fleet-wide manual restart; auto-recover adds a "switch back on" path that must restore everything a revoke turned off.
Recommendation: A because re-enabling a key is as deliberate as disabling it, the proof is the same one boot uses, and nobody should have to restart a whole fleet by hand (systems over heroes).
Note: options differ in kind, not coverage — no completeness score.
Net: hands-free recovery with one more tested path, against a manual restart of every node.
Header: Recovery
Options:
A) Auto-recover (recommended)
On the first re-check after a revoke where the stored key unwraps and its check matches, swap the AEAD back, re-send the CA to the gateway, return health to ok, reset the counter and write a `key_recovered` audit event. Effort S (human ~1d / CC ~1h), risk low; tested revoke → re-enable → recover. ✅ An accidental revoke heals within about 5 minutes with no one touching the fleet. ✅ Uses the same proof as boot, so it cannot recover with a wrong key. ❌ One more path that must restore everything the revoke turned off, and must be tested as such.
B) Restart only
A revoked node stays stopped until an operator restarts it; the boot unwrap then proves the key. Effort S (nothing extra), risk low. ✅ No recovery code: a boot is the only way back. ✅ A human always decides when service returns. ❌ An accidental revoke means restarting every node in the fleet by hand.

State: approved
Actual answer: A) Auto-recover (D12, 2026-10-25)
Accepted scope: on the first re-check after a revoke where the stored key unwraps and its check matches, the loop swaps the AEAD back, re-sends the CA to the gateway, returns health to ok, resets the counter and writes a `key_recovered` audit event (new Kind); a re-revoke needs N revoked results again; a revoke → re-enable → recover test (unit + live UC); §10, Phase 4 and the gate table updated.
History: none

### E5: which limiter numbers are settings
Finding: Section 2 finding 1, P3, confidence 8/10, Design §5 "Limit in one place" and "Background work never blocks a create", reviewer: eng review (Claude)
Plan baseline: open (blocks Phase 1); the plan already names `SB_SECRET_PROVIDER_MAX_INFLIGHT` (default 8)
Runtime evidence: none measured yet (Phase 0); CloudHSM limits sessions per client and vendor partitions differ [in-distribution knowledge]; the repo keeps config-default rationale in `setup/config-defaults.md`
Comparison grid:

```text
Commitment                     | Current (plan)                 | A (one setting)                       | B (all settings)                     | C (all hard-coded)
foreground in-flight cap       | SB_SECRET_PROVIDER_MAX_INFLIGHT| setting, default 8                    | setting, default 8                   | constant 8
reserved create slot           | 1 [estimated]                  | constant 1                            | setting                              | constant 1
background budget              | 2 [estimated]                  | constant 2                            | setting                              | constant 2
backoff ceiling                | unspecified                    | constant (inside caller deadline)     | setting                              | constant
helper session pool (eng D5)   | foreground + background        | MAX_INFLIGHT + 2                      | sum of settings                      | 10
config-defaults.md rows        | n/a                            | 1                                     | 4                                    | 0
effort                         | n/a                            | S (human ~2h / CC ~15min)             | S (human ~4h / CC ~30min)            | S
```

Question D13:
D13 — E5: Which of the key-store traffic limits should operators be able to change?
Project: plans/customer-key-custody on PR #784; Section 2 finding 1 (P3).
ELI10: sandboxd limits how many key-store calls run at once: 8 for normal work, 1 of those kept free for creates, 2 more for background jobs, plus a retry backoff. HSMs differ a lot in how many sessions they allow, so an operator may need to lower the main number for their HSM. The other three are internal balancing numbers nobody has measured yet; making them settings adds knobs that are hard to explain and easy to break.
Stakes if we pick wrong: no setting at all can leave a small HSM overloaded; four settings invite misconfiguration nobody can reason about.
Recommendation: A because the one number that depends on the customer's hardware becomes a setting, and the rest stay constants until Phase 0 measurements give a reason (avoid premature abstraction).
Note: options differ in kind, not coverage — no completeness score.
Net: one setting tied to real hardware limits, against four knobs or none.
Header: Limiter settings
Options:
A) One setting (recommended)
Keep `SB_SECRET_PROVIDER_MAX_INFLIGHT` (default 8) as the only setting; the reserved create slot (1), background budget (2) and backoff ceiling are constants with comments explaining them. Effort S (human ~2h / CC ~15min), risk low. ✅ Operators can fit the cap to their HSM's session limit. ✅ One row in `setup/config-defaults.md`, easy to explain. ❌ Changing the internal balance later needs a code change.
B) All settings
Make the reserved slot, background budget and backoff ceiling settings too. Effort S (human ~4h / CC ~30min), risk medium. ✅ Every number can be tuned in the field. ✅ No release needed to rebalance. ❌ Four knobs with no measurements behind them, which operators can set into a state where creates starve.
C) All hard-coded
No settings; every number is a constant. Effort S, risk medium. ✅ Nothing to misconfigure. ✅ Simplest code. ❌ An HSM with fewer sessions than 10 cannot be supported without a new build.

State: approved
Actual answer: A) One setting (D13, 2026-10-25)
Accepted scope: `SB_SECRET_PROVIDER_MAX_INFLIGHT` (default 8) is the only limiter setting, with a `setup/config-defaults.md` row; the reserved create slot (1), background budget (2) and backoff ceiling are commented constants; the helper session pool is MAX_INFLIGHT + 2; §5, the gate table and "Decisions needed" E5 updated.
History: none

### E10: one helper for secret-file permissions
Finding: Section 2 finding 2, P3, confidence 9/10, `pkg/secrets/wrap_key_loader.go:72`, reviewer: eng review (Claude)
Plan baseline: CEO Section 5 proposed "one helper used by the upstream wrap key, the PIN file and the wrapped server-key file"; not individually approved
Runtime evidence: `LoadUpstreamWrapKeyRing` refuses group/other bits (`if mode&0o077 != 0`, `:72`) **and** any write bit (`if mode&0o200 != 0`, `:75`), wanting 0400. The wrapped server-key file is written and rewritten by sandboxd itself at 0600 (§3, §11), so it must allow the owner write bit; the PIN file allows 0400 or 0600 (§2 settings)
Shared-code rubric: callers = 1 existing (`LoadUpstreamWrapKeyRing`, `wrap_key_loader.go:72`), 2 proposed (PIN file loader, Phase 3; wrapped-file loader, Phase 4: plan assumptions). Common contract: "refuse group or other permission bits". Difference: only the upstream key also refuses the owner write bit, so that check stays at its caller. Lines: implementation ~6 removed, ~10 added (helper + error text), saves ~4 net across 3 callers [estimated]; tests: one table test replaces three.
Comparison grid:

```text
Commitment                       | Current               | A (small shared helper)                     | B (three inline checks)
group/other-bit rule             | inline in 1 place      | `refuseGroupOtherBits(path)` in pkg/secrets, | copied into the PIN and wrapped-file loaders
                                 |                       | used by all 3 callers                       |
owner write-bit rule (0400 only) | upstream key only      | stays inline at the upstream key            | stays inline at the upstream key
error text                       | one wording            | one wording for all 3                       | three wordings
tests                            | 1                      | 1 table test for the helper                 | 3
net lines                        | n/a                    | about -4 implementation, fewer test lines   | about +12
effort                           | n/a                    | S (human ~1h / CC ~10min)                   | S (human ~1h / CC ~10min)
```

Question D14:
D14 — E10: Should the three "is this secret file locked down?" checks share one small helper?
Project: plans/customer-key-custody on PR #784; Section 2 finding 2 (P3).
ELI10: Three files hold sensitive material: the existing upstream wrap key, the new HSM PIN file and the new wrapped server key. Each must refuse to load if anyone besides the owner can read it. Today that check exists once (wrap_key_loader.go:72). One small shared function gives all three the same rule and the same error message, tested once. The existing file's extra "must not be writable" rule stays where it is, because sandboxd itself rewrites the wrapped key file.
Stakes if we pick wrong: copies can drift so one file quietly accepts looser permissions; a helper adds one tiny function.
Recommendation: A because the same security rule should live in one tested place, and the helper stays tiny by leaving the caller-specific write rule outside it (shared code only when it improves reliability).
Note: options differ in kind, not coverage — no completeness score.
Net: one tested rule for three files, against three copies that can drift.
Header: File-mode helper
Options:
A) Small shared helper (recommended)
Add `refuseGroupOtherBits(path)` to `pkg/secrets`, used by the upstream wrap key, PIN file and wrapped-file loaders; the upstream key keeps its extra write-bit check inline. Effort S (human ~1h / CC ~10min), risk low; one table test. ✅ One rule, one message, one test for every secret file. ✅ A future secret file gets the right check by calling one function. ❌ The upstream key's loader changes slightly, so its existing tests must still pass unchanged.
B) Three inline checks
Copy the group/other check into the two new loaders and leave the existing one alone. Effort S (human ~1h / CC ~10min), risk low. ✅ No change to existing code. ✅ Each loader reads on its own. ❌ Three copies of a security rule that can drift apart over time.

State: approved
Actual answer: A) Small shared helper (D14, 2026-10-25)
Accepted scope: `refuseGroupOtherBits(path)` in `pkg/secrets`, used by `LoadUpstreamWrapKeyRing` (its write-bit check stays inline), the PIN file loader and the wrapped-file loader; one table test; existing `wrap_key_loader_test.go` stays green unchanged; §5 updated.
History: none

### R-REG: regression contract for changed existing behavior
Finding: Section 3 regression rule, CRITICAL (existing behavior at risk), confidence 9/10, reviewer: eng review (Claude)
Plan baseline: the changes themselves are approved (CEO-A1 503 mapping, CEO-E2 awskms mapping, eng D3 comparison, eng D14 helper, custody=file default unchanged); no regression contract recorded yet
Runtime evidence: existing tests: `TestMapAWSKMSError` (`pkg/secrets/awskms_test.go:56`), `TestLoadUpstreamWrapKeyRing_RejectsLooseMode` (`wrap_key_loader_test.go:82`), put-outbox conflict cases (`internal/store/cluster_secret_put_outbox_test.go`), `testProviderContract` (`provider_contract_test.go:17`), `classify_test.go`
Behaviors to preserve and intended differences:

```text
Behavior                                  | Preserve                                         | Intended difference
awskms error mapping                      | Throttled, AccessDenied, other codes unchanged   | Disabled, NotFound, InvalidState+PendingDeletion -> ErrKeyRevoked
API error classes                         | every non-provider error status unchanged        | five provider classes -> 503 with stable codes
PutClusterSecret                          | stale gen rejected; tomb rules; payload conflict  | same gen + only WrappedKey changed -> idempotent
upstream wrap key loader                  | 0400 required; looser or writable refused        | none (helper extraction only)
custody=file boot, local provider         | NewCipher env/file/generate exactly as today;     | none
                                          | cluster key check unchanged                      |
awskms create path under normal load      | same results as today                            | now passes through limitedWrapper
```

Comparison grid:

```text
Commitment                     | Current      | A (extend existing tables)                    | B (separate regression files)
where assertions live          | n/a          | new rows in the existing table tests above,   | new *_regression_test.go per package pinning
                               |              | existing rows unchanged                       | today's behavior, then existing tests edited
intended differences           | n/a          | the changed rows say what changed and why     | in the regression files
"custody=file unchanged"       | n/a          | rows in secrets_test.go and config_test.go    | a regression file per package
duplicate coverage             | n/a          | none                                          | some overlap with existing tables
effort                         | n/a          | S (human ~1d / CC ~1h)                        | S-M (human ~2d / CC ~2h)
```

Question D15:
D15 — R-REG: How do we prove the existing behavior we are not changing stays the same?
Project: plans/customer-key-custody on PR #784; Section 3 regression rule (existing behavior at risk).
ELI10: Several approved changes touch code that already works: how AWS KMS errors are classified, the HTTP status for key-store errors, how a peer accepts a secret copy, the upstream key's permission check, and the default boot path when nothing new is turned on. Each needs tests that fail if anything other than the intended change moves. The question is where those tests live, not whether to write them.
Stakes if we pick wrong: a quiet change to existing behavior (for example, the default boot path) ships unnoticed to every current install.
Recommendation: A because the repo's style is table-driven tests and these behaviors already have tables; adding rows keeps one source of truth per behavior (match the existing harness).
Note: options differ in kind, not coverage — no completeness score.
Net: new rows in the existing tables, against a parallel set of regression files.
Header: Regression tests
Options:
A) Extend existing tables (recommended)
Add rows to `TestMapAWSKMSError`, `classify_test.go`, the put-outbox and store tests, `wrap_key_loader_test.go`, `secrets_test.go`, `config_test.go` and the provider contract run; existing rows stay unchanged and each changed row states the intended difference. Effort S (human ~1d / CC ~1h), risk low. ✅ One source of truth per behavior, in the style the repo already uses. ✅ A reviewer sees the intended difference next to the unchanged cases. ❌ The preserve-cases are spread across seven test files instead of one place.
B) Separate regression files
Add a `*_regression_test.go` per package that pins today's behavior before any change lands, then edit the existing tests. Effort S-M (human ~2d / CC ~2h), risk low. ✅ The whole "must not change" contract is easy to find. ✅ Written first, it catches a change even if an existing test is edited. ❌ Overlaps the existing tables, so two places must be kept in step.

State: approved
Actual answer: A) Extend existing tables (D15, 2026-10-25)
Accepted scope: regression rows added to `TestMapAWSKMSError`, `classify_test.go`, the put-outbox and store tests, `wrap_key_loader_test.go`, `secrets_test.go`, `config_test.go` and the provider contract run; existing rows unchanged; each changed row states its intended difference; the preserve/difference table above becomes the Testing section's regression contract.
History: none

### E3: the PKCS#11 key-wrap fallback for HSMs without AES-GCM
Finding: Section 3, P3, confidence 7/10, Design §2 "No-GCM fallback ... Ship it only if Phase 0 finds a target HSM without GCM", reviewer: eng review (Claude)
Plan baseline: recommended "only if Phase 0 needs it"; open (blocks Phase 3, after Phase 0)
Runtime evidence: none (no HSM tested yet); F3 (D14 of the CEO review) chose AWS CloudHSM first, whose PKCS#11 library documents AES-GCM with an HSM-generated IV (AWS docs cited in the plan)
Comparison grid:

```text
Commitment                         | Current                         | A (decide after Phase 0)                  | B (ship it now)
CKM_AES_KEY_WRAP_PAD code path      | not built                       | not built unless Phase 0 finds a target   | built and tested in Phase 3
                                    |                                 | HSM without AES-GCM                       |
AAD on the wrapped key              | GCM AAD                         | GCM AAD                                   | GCM AAD, or none on the fallback (payload
                                    |                                 |                                           | AAD still binds identity)
test matrix                         | GCM                             | GCM                                       | GCM + key-wrap on SoftHSM2
what Phase 0 must record            | GCM IV behavior                 | + "AES-GCM available" per target HSM      | same
effort                              | n/a                             | S now (zero implementation work)          | S-M (human ~2d / CC ~2h)
```

Question D16:
D16 — E3: Should we build a second HSM wrapping method for HSMs that lack AES-GCM, or wait until we meet one?
Project: plans/customer-key-custody on PR #784; Section 3 (P3).
ELI10: The HSM provider wraps keys with AES-GCM, which almost every modern HSM supports, including AWS CloudHSM, the one we certify first. A few older HSMs only offer a different wrapping method that cannot carry the extra "this belongs to sandbox X" tag. The design stays safe without that tag, because the secret itself carries it, but it is a second code path to build and test.
Stakes if we pick wrong: building it now adds an untested-in-the-field path; waiting means a customer with an old HSM gets "not supported" until we add it.
Recommendation: A because no target HSM needs it today, CloudHSM supports AES-GCM, and Phase 0 records the fact for each HSM we test (do not build for problems that do not exist yet).
Note: options differ in kind, not coverage — no completeness score.
Net: no second path until a real HSM needs it, against support for older HSMs from day one.
Header: Key-wrap fallback
Options:
A) Decide after Phase 0 (recommended)
Build only AES-GCM now; Phase 0 records "AES-GCM available" for every HSM it tests, and the fallback is built only if one of them lacks it. Effort S now (zero implementation work), risk low. ✅ One wrapping path to build, test and support. ✅ The decision is made on a measured fact, not a guess. ❌ A customer with an HSM lacking AES-GCM waits for a follow-up.
B) Ship it now
Build `CKM_AES_KEY_WRAP_PAD` as a configured fallback and test it on SoftHSM2. Effort S-M (human ~2d / CC ~2h), risk medium. ✅ Older HSMs work on day one. ✅ No follow-up needed later. ❌ A second code path that no tested customer HSM needs yet.

State: approved
Actual answer: A) Decide after Phase 0 (D16, 2026-10-25)
Accepted scope: build AES-GCM only; Phase 0 records "AES-GCM available" for each HSM it tests; the key-wrap fallback is built only if a tested target lacks AES-GCM (no implementation now); Phase 0 row and the gate table updated.
History: none

### E8: retry once when the key store is briefly unavailable
Finding: Section 4 finding 1, P2, confidence 7/10, CEO Section 1 production-failure table (Vault row), reviewer: eng review (Claude)
Plan baseline: `limitedWrapper` retries only `ErrProviderThrottled` (Design §5); E8 open (blocks Phase 1)
Runtime evidence: no retry exists for any provider class today (`internal/service/metrics.go:316` only counts); Vault returns 503 while a standby is promoted [in-distribution knowledge, unverified]; AWS KMS and HSM HA clients mostly fail over below the caller
Comparison grid:

```text
Commitment                        | Current                 | A (one short retry, foreground)               | B (no retry)
create during a brief blip        | 503 key_store_unavailable| one retry after 100-300 ms jitter, if the      | 503 key_store_unavailable
                                  |                         | caller deadline has room; then 503            |
multi-second Vault handover       | 503                     | 503 (retry lands inside the handover)         | 503
background calls (re-check, sweep)| n/a                     | no retry; the next tick tries again           | no retry
counts toward a revoke            | no                      | no (Unavailable is never a revoke)            | no
added latency on a real outage    | none                    | up to ~300 ms before the 503                  | none
effort                            | n/a                     | S (human ~2h / CC ~15min)                     | S (nothing extra)
```

Question D17:
D17 — E8: When the key store answers "temporarily unavailable", should a create retry once before failing?
Project: plans/customer-key-custody on PR #784; Section 4 finding 1 (P2).
ELI10: Short key-store hiccups happen: a dropped connection, a request that lands at the end of a Vault handover, a brief network blip. Today any of them fails the create. One quick retry, about a quarter second later and only if the request still has time left, hides those. It does not hide a handover that lasts several seconds; that still fails with a clear "try again" error. Background jobs do not need it: they try again on their next run.
Stakes if we pick wrong: no retry means customer-visible failures on every brief blip; a retry adds up to ~300 ms before a real outage's error.
Recommendation: A because a single bounded retry hides brief blips at almost no cost and never retries past the caller's deadline (thorough handling over speed).
Note: options differ in kind, not coverage — no completeness score.
Net: one bounded retry that hides brief blips, against failing fast every time.
Header: Unavailable retry
Options:
A) One short retry (recommended)
For foreground calls only, retry `ErrProviderUnavailable` once after 100-300 ms of jitter if the caller's deadline leaves room; background calls never retry. Effort S (human ~2h / CC ~15min), risk low; unit test with a fake that fails once. ✅ Brief blips and the tail of a Vault handover never reach the customer. ✅ Bounded: one retry, inside the deadline, never on background work. ❌ A multi-second handover still fails, and a real outage's 503 arrives up to ~300 ms later.
B) No retry
Fail fast with 503 `key_store_unavailable` and let the client retry. Effort S (nothing extra), risk low. ✅ Simplest behavior, the error arrives immediately. ✅ Clients with their own retry are not double-retried. ❌ Every brief blip shows up as a failed create.

State: approved
Actual answer: A) One short retry (D17, 2026-10-25)
Accepted scope: `limitedWrapper` retries `ErrProviderUnavailable` once, for foreground calls only, after 100-300 ms of jitter if the caller's deadline leaves room; background calls never retry; a unit test with a fake that fails once; §5, the Section 2 rescue table and the gate table updated.
History: an earlier draft claimed the retry "rides over most handovers"; corrected before asking, since a multi-second handover still fails.

### CEO-E2c: re-check defaults
Finding: Section 4 finding 2, P3, confidence 8/10, Design §10 "default 5 minutes", "default 3, so about 15 minutes", reviewer: eng review (Claude)
Plan baseline: 5 min × 3 written into the claim ("about 15 minutes") as [estimated]; CEO-E2c open (blocks Phase 4, after Phase 0); both stay settings (`SB_SECRET_PROVIDER_RECHECK_INTERVAL`, `SB_SECRET_PROVIDER_REVOKE_AFTER`)
Runtime evidence: none measured; fleet load = nodes ÷ interval (one unwrap per node per interval, Design §10); the gateway self-drop uses the same bound (Design §10)
Comparison grid:

```text
Commitment                  | Current (plan)        | A (5 min x 3)           | B (1 min x 3)            | C (15 min x 2)
revoke bound in the claim   | ~15 min               | ~15 min                 | ~3 min                   | ~30 min
fleet load at 2,000 nodes   | ~7 calls/s [est.]     | ~7 calls/s              | ~33 calls/s              | ~2 calls/s
false-trip protection       | 3 deliberate signals  | 3 in a row              | 3 in a row (3 min)       | 2 in a row
gateway self-drop bound     | ~15 min               | ~15 min                 | ~3 min (a slow sandboxd  | ~30 min
                            |                       |                         | restart could drop it)   |
still settings              | yes                   | yes                     | yes                      | yes
effort                      | n/a                   | S (as planned)          | S                        | S
```

Question D18:
D18 — CEO-E2c: What revoke window should the defaults give: about 15 minutes, about 3 minutes, or about 30 minutes?
Project: plans/customer-key-custody on PR #784; Section 4 finding 2 (P3).
ELI10: Each node re-checks the key every few minutes and stops after a few "revoked" answers in a row. Checking every 5 minutes, 3 times, means a revoke bites within about 15 minutes and the whole fleet makes about 7 key-store calls a second. Checking every minute cuts the window to about 3 minutes but adds five times the load, and also shrinks the grace the egress gateway gives a restarting sandboxd. Operators can change both numbers; this only picks the default the docs promise.
Stakes if we pick wrong: too long and the promised cut-off feels slow to a security buyer; too short and key stores carry more load and gateways can drop their CA during a slow restart.
Recommendation: A because 15 minutes is a credible cut-off for a deliberate revoke, keeps fleet load trivial, and leaves the gateway a safe restart grace; buyers who need faster can set a shorter interval (boring by default).
Note: options differ in kind, not coverage — no completeness score.
Net: a 15-minute default with light load, against a faster cut-off at five times the load or a slower one at a third.
Header: Re-check default
Options:
A) 5 min x 3 (recommended)
Re-check every 5 minutes; trip after 3 revoked results in a row; the claim says "about 15 minutes". Effort S (as planned), risk low. ✅ About 7 key-store calls per second across 2,000 nodes. ✅ The gateway's self-drop grace stays well above a normal sandboxd restart. ❌ A buyer who wants a faster cut-off has to change the setting.
B) 1 min x 3
Re-check every minute; trip after 3; the claim says "about 3 minutes". Effort S, risk medium. ✅ The fastest default cut-off. ✅ A strong line in a security review. ❌ Five times the key-store load, and a sandboxd restart slower than ~3 minutes would make the gateway drop its CA.
C) 15 min x 2
Re-check every 15 minutes; trip after 2; the claim says "about 30 minutes". Effort S, risk low. ✅ The lightest load, about 2 calls per second. ✅ The fewest background entries in the key store's audit log. ❌ A 30-minute cut-off reads as slow to a security buyer.

State: approved
Actual answer: A) 5 min x 3 (D18, 2026-10-25)
Accepted scope: defaults `SB_SECRET_PROVIDER_RECHECK_INTERVAL=5m` and `SB_SECRET_PROVIDER_REVOKE_AFTER=3` (both settings, documented in `setup/config-defaults.md`); the claim keeps "about 15 minutes"; the gateway self-drop bound follows; the Vault error text stays a Phase 0 item; §10 and the gate table updated.
History: option C's second pro was corrected before asking (key-store outages never count toward a revoke in any option).

### CEO-E4a: sweep cadence
Finding: Section 4 finding 3, P3, confidence 8/10, Design §11 "It runs at boot and then on a cadence (CEO-E4a)", reviewer: eng review (Claude)
Plan baseline: boot plus an undecided cadence, on the 2-slot background budget, with a random start delay (Design §5 "Sweep load after a rotation"); CEO-E4a open (blocks Phase 4b)
Runtime evidence: a pass reads every local row once by primary-key pages and parses only the `WrappedKey` prefix (CEO Section 7); rewrap calls happen only for stale rows; on Vault each pass also reads the key's latest version once (`read` on `<mount>/keys/<key>`), so an idle pass is a local scan plus that one read; operators retire a version only after every member's stale gauge reads 0 (§11)
Comparison grid:

```text
Commitment                          | Current      | A (boot + hourly)                    | B (boot + daily)                     | C (boot only)
wait after a rotation before retire | undecided    | up to ~1 h (+ start jitter)          | up to ~24 h                          | until every node restarts
local scan cost when nothing stale  | n/a          | 24 paged scans/day/node              | 1 scan/day/node                      | 1 per boot
key-store calls                     | stale rows   | stale rows, plus 1 version read per  | stale rows, plus 1 version read per  | stale rows, plus 1 read
                                    |              | pass on Vault (~0.6/s at 2,000 nodes) | pass on Vault                        | per boot
start spread across the fleet       | random delay | random delay up to 1 h               | random delay up to 24 h              | follows restarts
new setting                         | none         | none (constant, per eng D13)         | none (constant)                      | none
effort                              | n/a          | S (human ~1h / CC ~10min)            | S                                    | S
```

Question D19:
D19 — CEO-E4a: After a key rotation, how often should each node look for old-version rows to rewrap?
Project: plans/customer-key-custody on PR #784; Section 4 finding 3 (P3).
ELI10: After a customer rotates their key, every node re-wraps its stored keys onto the new version in the background, and only when every node's "stale" count is zero can the old version be retired. Looking every hour means the wait after a rotation is about an hour; daily means about a day; boot-only means someone must restart every node. A look with nothing to do is a quick local scan plus, on Vault, one small call to read the key's version, so hourly costs almost nothing.
Stakes if we pick wrong: daily or boot-only makes key retirement slow or manual; much more often than hourly adds local scanning for no gain.
Recommendation: A because an hour is a reasonable wait for a deliberate rotation, the idle scan is cheap, and nobody has to restart the fleet to finish a rotation (systems over heroes).
Note: options differ in kind, not coverage — no completeness score.
Net: an hour's wait with cheap idle scans, against a day's wait or a manual fleet restart.
Header: Sweep cadence
Options:
A) Boot + hourly (recommended)
Sweep at boot (after the API is serving) and then every hour, with a random start delay of up to an hour across the fleet. Effort S (human ~1h / CC ~10min), risk low. ✅ A rotation finishes on its own within about an hour. ✅ An idle pass is a paged local scan plus, on Vault, one version read. ❌ 24 local scans a day on every node, even when nothing is stale.
B) Boot + daily
Sweep at boot and then once a day, with a random start delay of up to a day. Effort S, risk low. ✅ The least background work. ✅ Spreads any rotation load over a whole day. ❌ Operators wait up to a day before they can retire an old key version.
C) Boot only
Sweep only at boot; a rotation completes when every node has restarted. Effort S, risk medium. ✅ No background timer at all. ✅ Simplest to reason about. ❌ Finishing a rotation needs a restart of every node in the fleet.

State: approved
Actual answer: A) Boot + hourly (D19, 2026-10-25)
Accepted scope: the `key_custody` loop sweeps at boot (after the API is serving) and then every hour as a constant, with a random start delay of up to an hour; on Vault each pass reads the key's latest version once; §5, §11 and the gate table updated.
History: the idle-pass cost was corrected before asking (on Vault a pass also reads the key version once).

### OV1: equal-content peer copies keep which wrapping (reopens D3)
Finding: outside voice OV1, High, confidence 9/10, eng D3 accepted scope, reviewer: codex (verified by eng review)
Plan baseline: D3 (approved A): same generation and same content is idempotent and **keeps the incoming bytes**
Runtime evidence: each node's sweep rewraps only its own copies (§11); the put-outbox resends whatever bytes the sender holds; `PutClusterSecret` already skips the row rewrite when bytes are identical (`internal/store/store.go:5888`)
Reason for reopening: new evidence. A delayed copy sealed before the sender's sweep can arrive after the receiver's own sweep, put the old wrapping back, and make a row that already counted as current stale again after the operator retires the old version.
Comparison grid:

```text
Commitment                         | Current (D3)                   | A (apply: keep existing)           | B (keep D3)           | C (investigate)        | D (defer)
same gen, equal content, new bytes | write incoming bytes           | no rewrite; keep existing bytes;   | write incoming bytes  | D3 stays until a       | D3 stays; OV1 open
                                   |                                | apply tomb/outbox transitions; ACK |                       | bounded probe          |
receiver's own swept row           | can be overwritten by an older | never overwritten                  | can be overwritten    | unchanged              | unchanged
                                   | wrapping                       |                                    |                       |                        |
who rewraps the receiver's copy    | sender (by resending)          | the receiver's own sweep           | sender                | unchanged              | unchanged
payload differs, same gen          | conflict                       | conflict                           | conflict              | conflict               | conflict
effort                             | S                              | S (a smaller change than D3)       | S                     | S (study only)         | S
```

Question D20:
D20 — OV1 (reopens D3): When a peer copy arrives with the same secret but a different wrapping, keep the copy already on disk or take the incoming one?
Project: plans/customer-key-custody on PR #784; outside voice finding OV1 (High), checked against D3.
ELI10: In D3 we chose to accept a peer's copy that differs only in its wrapped key and to store the incoming bytes. The outside reviewer found the catch: an older copy, sent before the sender re-wrapped it, can arrive after this node has already re-wrapped its own copy, and would put the old wrapping back. If the old key version is then retired, that row breaks. Keeping whatever is already on disk avoids it, because every node re-wraps its own copies anyway.
Stakes if we pick wrong: keeping D3 can silently undo a rotation on some nodes and break those rows when the old version is retired.
Recommendation: A because each node already owns rewrapping its own copies, so the safe rule is to never let a peer overwrite them (explicit over clever).
Note: options differ in kind, not coverage — no completeness score.
Net: never overwrite a local wrapping, against D3's simpler "take what arrives".
Header: Peer copy rule
Options:
A) Apply: keep existing
For the same generation and equal content, do not rewrite the row: keep the bytes already on disk, still apply the tomb and outbox transitions, and return success; a different payload is still a conflict. Effort S (smaller than D3), risk low; a test sends a pre-sweep copy after the receiver's sweep and checks the receiver's wrapping survives. ✅ A rotation can never be undone by a late peer copy. ✅ Matches who owns rewrapping: each node's own sweep. ❌ A receiver's copy is only as fresh as its own sweep, not the sender's.
B) Keep D3
Store the incoming bytes as D3 says. Effort S, risk high. ✅ No change from the approved answer. ✅ Peers adopt the sender's wrapping immediately. ❌ A late, older copy can undo a rotation and break rows after retirement.
C) Investigate first
Keep D3 for now and spend at most half a day probing outbox timing to see how often a late copy can land after a sweep; then ask again. Effort S (study only), risk medium. ✅ Decides on measured timing. ✅ No design change yet. ❌ The race exists whatever the timing shows, so the probe changes little.
D) Defer
Leave D3 in place and keep OV1 open as an unresolved decision. Effort S, risk high. ✅ No change now. ✅ Revisit during Phase 4b. ❌ Phase 4b would start with a known way to undo rotations.

State: approved
Actual answer: A) Apply: keep existing (D20, 2026-10-25)
Accepted scope: same generation and equal content (ignoring `WrappedKey`) is idempotent and keeps the bytes already on disk: no row rewrite, the tomb and outbox transitions still apply, success is returned; a different payload is still a conflict; a test sends a pre-sweep copy after the receiver's sweep and checks the receiver's wrapping survives; §11 and the test list updated.
History: D3 (approved A, 2026-10-21) chose "compare without the key" and "keep the incoming bytes"; this row reopens only the "which bytes" half. The comparison itself (ignore `WrappedKey`) stays approved.

### OV2: what the egress gateway drops on a revoke
Finding: outside voice OV2, High, confidence 9/10, `internal/egress/proxy/inspect.go:108-110` and `:251`, reviewer: codex (verified by eng review)
Plan baseline: CEO-E2R (D9, full stop) says inspected egress fails closed; §10 sends `clear_inspect_ca`, with a unit restart for an old gateway (eng D4)
Runtime evidence: `serveInspect` loads the inspector once at connection start (`ins := p.currentInspector()`), so established inspected connections keep using it; inject rules read `cur.Spec.Secrets[key]` and replace a header with the secret (`:251`); the gateway never writes those secrets to its snapshot (`internal/egress/snapshot.go:34`); its comment says a policy change can close inspected connections (`inspect.go:106-107`)
Comparison grid:

```text
Commitment                           | Current (D4 + §10)            | A (apply: full clear op)                 | B (keep)                 | C (investigate)       | D (defer)
new inspected handshakes after revoke| refused                       | refused                                  | refused                  | refused               | refused
established inspected connections    | keep running with the old CA  | closed by the gateway                    | keep running             | unchanged             | unchanged
injection secrets in gateway memory  | kept; inject rules still add  | dropped; inject rules deny with           | kept                     | unchanged             | unchanged
                                     | real credentials              | ReasonSecretMissing                      |                          |                       |
post-revoke Syncs from sandboxd      | unspecified                   | carry no secrets                         | unspecified              | unspecified           | unspecified
non-inspected egress                 | keeps working                 | keeps working                            | keeps working            | keeps working         | keeps working
old gateway (D4)                     | unit restart                  | unit restart (clears all three)          | unit restart             | unit restart          | unit restart
effort                               | n/a                           | S-M (human ~2d / CC ~2h)                 | S                        | S                     | S
```

Question D21:
D21 — OV2: On a revoke, should the egress gateway also cut existing inspected connections and forget the secrets it injects?
Project: plans/customer-key-custody on PR #784; outside voice finding OV2 (High), checked against inspect.go.
ELI10: The egress gateway inspects some HTTPS traffic and can add a real credential into outgoing requests for a sandbox (for example an API key header). Our revoke only stops new inspected connections. Connections already open keep using the old certificate, and the gateway keeps the credentials it adds, so a running sandbox can keep calling out with a customer secret after the revoke. The full stop you chose in the CEO review promises that stops.
Stakes if we pick wrong: a revoke looks complete while running sandboxes keep sending real customer credentials through already-open connections.
Recommendation: A because the full stop you approved (D9) promises AerolVM stops using customer secrets, and these are exactly such secrets (thorough handling over speed).
Note: options differ in kind, not coverage — no completeness score.
Net: a revoke that also ends open inspected sessions and injected credentials, against a revoke that only blocks new ones.
Header: Gateway on revoke
Options:
A) Apply: full clear op
`clear_inspect_ca` drops the CA, drops every sandbox's injection secrets and closes established inspected connections; inject rules then deny with `ReasonSecretMissing`; sandboxd's later Syncs carry no secrets while revoked; an old gateway is still restarted (D4), which clears all three. Effort S-M (human ~2d / CC ~2h), risk low; tested with an open keep-alive connection and an inject rule across a revoke. ✅ No customer credential leaves through AerolVM after a revoke. ✅ Non-inspected egress keeps working, as the full stop promised. ❌ Open inspected sessions in running sandboxes are cut mid-flight.
B) Keep the current design
Only refuse new inspected handshakes. Effort S, risk high. ✅ No new gateway behavior. ✅ No connections are cut. ❌ Running sandboxes keep sending injected customer secrets after a revoke, contradicting D9.
C) Investigate first
Spend at most a day measuring how long inspected connections live and how inject rules are used in practice; then ask again. Effort S (study only), risk medium. ✅ Decides on real usage. ✅ No change yet. ❌ The leak exists for any connection that outlives the bound, whatever the numbers say.
D) Defer
Keep the current design and leave OV2 open. Effort S, risk high. ✅ No change now. ✅ Revisit in Phase 4. ❌ Phase 4 starts with a known gap in the full stop.

State: approved
Actual answer: A) Apply: full clear op (D21, 2026-10-25)
Accepted scope: `clear_inspect_ca` drops the CA, drops every sandbox's injection secrets and closes established inspected connections; inject rules then deny with `ReasonSecretMissing`; sandboxd's Syncs carry no secrets while the node is revoked; an old gateway is still restarted (D4); on auto-recovery (D12) the next Sync and `set_inspect_ca` restore them; a test with an open keep-alive inspected connection and an inject rule across a revoke; §10, tests and Phase 4 updated.
History: none

### OV3: the two-step switch for AWS KMS (reopens D9 wording)
Finding: outside voice OV3, High, confidence 9/10, Design §12 "If that fails and the provider is `awskms`, it tries AWS KMS", reviewer: codex (verified by eng review)
Plan baseline: D9 (approved A): untagged rows try the server key, then AWS KMS **if the provider is `awskms`**; D8 (approved A): a node opens any **tagged** row whose backend it has settings for
Runtime evidence: AWS KMS rows carry no tag (§4); during a `local → awskms` switch, an unswitched node (provider still `local`, AWS settings already added in step 1) never tries AWS KMS for an untagged row, so D8's no-window promise fails for exactly this path
Reason for reopening: contradiction between two approved answers, found by the outside voice.
Comparison grid:

```text
Commitment                           | Current (D8 + D9)                 | A (apply: settings decide)         | B (keep D9 wording)          | C (investigate) | D (defer)
untagged row, node has AWS settings  | AWS tried only if provider=awskms | AWS tried whenever AWS settings    | only if provider=awskms      | unchanged       | unchanged
                                     |                                   | are present                        |                              |                 |
local -> awskms two-step switch      | has a failover window             | no window                          | window (documented)          | unchanged       | unchanged
local -> vault / pkcs11 switch       | no window (tags)                  | no window                          | no window                    | no window       | no window
untagged row on a node without AWS   | server key only                   | server key only                    | server key only              | same            | same
effort                               | n/a                               | S (human ~2h / CC ~15min)          | S (docs)                     | S               | S
```

Question D22:
D22 — OV3 (reopens D9 wording): For old untagged rows, should a node try AWS KMS whenever it has AWS KMS settings, not only when AWS KMS is its sealing provider?
Project: plans/customer-key-custody on PR #784; outside voice finding OV3 (High), a conflict between D8 and D9.
ELI10: D8 made switching providers safe by letting every node open the new kind of row as soon as it has that provider's settings, before it starts sealing with it. That works for Vault and HSM rows because they are labelled. AWS KMS rows carry no label, and D9's rule only tries AWS KMS when AWS KMS is the node's sealing provider. So during a switch from local to AWS KMS, a node that has not switched yet cannot open new rows, which is the very gap D8 closed. Trying AWS KMS whenever the node has AWS settings fixes it.
Stakes if we pick wrong: local-to-AWS-KMS adopters get the failover gap D8 was meant to remove.
Recommendation: A because it makes D8's promise true for every provider with a one-word change to D9's rule (fix the conflict where the rule lives).
Note: options differ in kind, not coverage — no completeness score.
Net: one consistent "settings decide" rule for every provider, against a documented gap for AWS KMS adopters.
Header: AWS switch
Options:
A) Apply: settings decide
An untagged row opens with the server key first, then with AWS KMS whenever AWS KMS settings are present, whatever the sealing provider; test the `local → awskms` two-step switch separately from Vault. Effort S (human ~2h / CC ~15min), risk low. ✅ The two-step switch has no window for any provider. ✅ One rule for tagged and untagged rows: the node's settings decide what it can open. ❌ A node with AWS settings but no AWS permissions makes one failed AWS call for a stray untagged row.
B) Keep D9's wording
Try AWS KMS only when it is the sealing provider; document that `local → awskms` keeps a short failover window. Effort S (docs), risk medium. ✅ No change to an approved rule. ✅ Nothing new to test. ❌ Local-to-AWS-KMS adopters lose failover copies during the switch.
C) Investigate first
Spend at most half a day checking whether any customer would switch local to AWS KMS rather than to Vault or HSM; then ask again. Effort S (study only), risk medium. ✅ Decides on real demand. ✅ No change yet. ❌ The rule conflict stays in the plan until then.
D) Defer
Keep D9's wording and leave OV3 open. Effort S, risk medium. ✅ No change now. ✅ Revisit in Phase 4b. ❌ The plan carries two approved rules that disagree.

State: approved
Actual answer: A) Apply: settings decide (D22, 2026-10-25)
Accepted scope: an untagged row opens with the server key first, then with AWS KMS whenever AWS KMS settings are present, whatever the sealing provider; the `local → awskms` two-step switch gets its own test and live UC, separate from Vault; §4, §12, the D9 record and the test list updated.
History: D9 (approved A, 2026-10-21) chose the trial order (server key, then AWS KMS when the provider is `awskms`); only the "when" condition is reopened.

### OV4: PKCS#11 key rotation across a cluster
Finding: outside voice OV4, High, confidence 8/10, Design §2 settings (`SB_SECRET_PKCS11_KEY_LABEL`, `SB_SECRET_PKCS11_DECRYPT_KEY_LABELS`) and §11 "Progress and retirement", reviewer: codex (verified by eng review)
Plan baseline: §11: rotate, wait for every member's stale gauge = 0, retire; labels are per-node settings
Runtime evidence: a `p11:` header naming a label the node does not list is `ErrDecryptFailed` (§2 label table), so a node switched to label B produces rows its unswitched peers reject; the stale gauge counts rows not on **that node's** current label, so "0 everywhere" can hold while nodes target different labels; Vault versions are global, so this is PKCS#11-only
Comparison grid:

```text
Commitment                       | Current (§11)                    | A (apply: staged rollout)                     | B (keep)                 | C (investigate) | D (defer)
order of a label rotation        | "rotate", unspecified            | 1) add B to DECRYPT labels on every node;     | unspecified              | unspecified     | unspecified
                                 |                                  | 2) set KEY_LABEL=B on every node; 3) wait;    |                          |                 |
                                 |                                  | 4) retire A                                   |                          |                 |
proof step 1 is done everywhere | none                             | `aerolvm_key_decryptable{backend,key}` info   | none                     | none            | none
                                 |                                  | gauge: every member lists B before step 2     |                          |                 |
proof every node targets B       | none                             | `aerolvm_key_current{backend,key}` info gauge  | none                     | none            | none
                                 |                                  | (both also in `sandboxd key status`)          |                          |                 |
retirement gate                  | stale = 0 on every member        | stale = 0 AND current key = B on every member | stale = 0                | same            | same
a node sealing B before peers    | peers reject B rows              | prevented by checking the decryptable gauge   | peers reject B rows      | same            | same
can open B                       |                                  | on every member before step 2                 |                          |                 |
Vault, AWS KMS                   | unaffected                       | unaffected (versions are global)              | unaffected               | same            | same
effort                           | n/a                              | S (human ~1d / CC ~1h)                        | S                        | S               | S
```

Question D23:
D23 — OV4: How do we rotate an HSM key across a cluster without nodes rejecting each other's copies?
Project: plans/customer-key-custody on PR #784; outside voice finding OV4 (High).
ELI10: With an HSM, each node is told which key label to use. If one node starts using the new label before the others know about it, the others cannot open what it writes. And "no stale rows anywhere" can look true while some nodes are still on the old label. The fix is the same two-step idea as the provider switch: first let every node open the new label and check that all of them report it, then switch every node to write with it, then check that every node reports the new label as current before retiring the old one.
Stakes if we pick wrong: an HSM rotation can break failover copies mid-rollout, or retire a label some node still writes with.
Recommendation: A because it reuses the proven two-step pattern and adds the one signal needed to prove retirement is safe (systems over heroes).
Note: options differ in kind, not coverage — no completeness score.
Net: a staged, checkable rotation, against an unspecified one that can break copies.
Header: HSM rotation
Options:
A) Apply: staged rollout
Document and test the four steps; add `aerolvm_key_decryptable{backend,key}` and `aerolvm_key_current{backend,key}` info gauges (both also in `sandboxd key status`); step 2 starts only when every member lists B as decryptable; the retirement gate becomes stale = 0 and current key = B on every member. Effort S (human ~1d / CC ~1h), risk low. ✅ Copies stay openable at every step of the rotation. ✅ Operators can prove every node moved before retiring. ❌ A rotation takes two rolling config changes instead of one.
B) Keep the current text
Leave §11's "rotate, wait, retire" as is. Effort S, risk high. ✅ No new gauge or runbook steps. ✅ One config change per rotation. ❌ A rotation can break copies mid-rollout and the retirement gate can be wrong.
C) Investigate first
Spend at most half a day checking how CloudHSM and SoftHSM handle two active labels at once; then ask again. Effort S (study only), risk medium. ✅ Confirms the HSM side before writing the runbook. ✅ No change yet. ❌ The ordering problem is in our config model, not the HSM, so the study changes little.
D) Defer
Keep the current text and leave OV4 open. Effort S, risk high. ✅ No change now. ✅ Revisit in Phase 4b. ❌ The first HSM rotation in the field could break failover copies.

State: approved
Actual answer: A) Apply: staged rollout (D23, 2026-10-25)
Accepted scope: a four-step PKCS#11 label rotation (add B to decrypt labels everywhere; switch `KEY_LABEL` to B everywhere; wait; retire A); `aerolvm_key_decryptable{backend,key}` and `aerolvm_key_current{backend,key}` info gauges, also in `sandboxd key status`; step 2 starts only when every member lists B as decryptable; retirement needs stale = 0 and current = B on every member; a live UC for the rotation; §11, Section 8 metrics and tests updated.
History: an earlier draft's boot warning was replaced before asking (a node can always decrypt its own current label, so the warning proved nothing).

### OV5: old plaintext copies after migrating to a wrapped key
Finding: outside voice OV5, High, confidence 9/10, `scripts/sandboxd-backup.sh:69` (`copy_if_exists "$config_dir" "$tmpdir/root/etc/sandboxd"`), reviewer: codex (verified by eng review)
Plan baseline: §3 "Backups" says the backup copies `state.db` and the raft directory and adds the wrapped file; the claim says "no long-lived key that decrypts AerolVM-held secrets is stored in plaintext outside your key store"
Runtime evidence: the backup also archives `/etc/sandboxd`, which holds `cluster.env` with `SB_CREDENTIAL_ENCRYPTION_KEY=<plaintext>` (fact 10); `sandboxd key wrap` wraps the **same** key, so every older backup, old cred bundle and old S3 bundle object version still decrypts data sealed after the migration; F1 only checks the node itself
Comparison grid:

```text
Commitment                        | Current                      | A (apply: honest claim + cleanup)        | B (rotate the key at migration)        | C (investigate) | D (defer)
claim for a fresh wrapped install | true                         | true                                     | true                                   | same            | same
claim for a migrated install      | true (wrong)                 | true only after old copies are destroyed;| true after the reseal                  | unchanged       | unchanged
                                  |                              | docs and custody report say so           |                                        |                 |
backup script                     | archives cluster.env key     | stops archiving the plaintext key line   | stops archiving it                     | unchanged       | unchanged
                                  |                              | and key file; keeps the wrapped file     |                                        |                 |
custody report                    | n/a                          | "migrated from plaintext: destroy old    | n/a                                    | n/a             | n/a
                                  |                              | backups/bundles" until acknowledged      |                                        |                 |
server-key rotation (non-goal)    | non-goal                     | stays a non-goal; TODO asked separately  | built now: new key + reseal of every   | non-goal        | non-goal
                                  |                              |                                          | row on every node                      |                 |
effort                            | n/a                          | S (human ~1d / CC ~1h)                   | XL (human ~4w / CC ~3d)                | S               | S
```

Question D24:
D24 — OV5: An install that migrates from a plain key file to a wrapped key keeps the same key, so old backups still unlock it. What do we do?
Project: plans/customer-key-custody on PR #784; outside voice finding OV5 (High), checked against the backup script.
ELI10: Wrapping protects the key from now on, but it is still the same key. Every backup taken before the migration archived /etc/sandboxd, including the plain key, and so did old copies of the cluster setup bundle. Anyone holding one of those can still decrypt data written after the migration. We can either say so plainly and give a cleanup checklist, or generate a brand-new key at migration and re-encrypt everything, which is a large job we listed as out of scope.
Stakes if we pick wrong: the docs would promise "no key on disk" to customers whose old backups still hold it.
Recommendation: A because it makes the claim true and checkable with a small change, while a full key rotation is a separate, much larger feature (asked as its own TODO).
Note: options differ in kind, not coverage — no completeness score.
Net: an honest claim with a cleanup checklist, against a full key rotation at migration.
Header: Old key copies
Options:
A) Apply: honest claim + cleanup
The claim covers a migrated install only after old copies are destroyed; the docs give a checklist (old backups, cred bundles, S3 bundle object versions, `cluster.env` history); the backup script stops archiving the plaintext key line and key file and keeps the wrapped file; `sandboxd key status` shows "migrated from plaintext" until the operator runs `sandboxd key ack-migration`. Effort S (human ~1d / CC ~1h), risk low. ✅ The claim is true for every install it covers. ✅ New backups never contain the plain key again. ❌ Migrated customers must find and destroy old copies by hand.
B) Rotate the key at migration
`sandboxd key wrap` makes a new server key and re-encrypts every sealed row (env, toolbox tokens, registry, mounts, egress CA, local cluster copies) on every node. Effort XL (human ~4w / CC ~3d), risk high. ✅ Old copies become useless the moment migration ends. ✅ No cleanup checklist. ❌ A large cross-node re-encryption that the plan lists as a non-goal, with its own failure modes.
C) Investigate first
Spend at most a day sizing a server-key rotation design; then ask again. Effort S (study only), risk medium. ✅ Decides with a real estimate for B. ✅ No change yet. ❌ The claim stays wrong in the plan until then.
D) Defer
Leave the claim as it is and keep OV5 open. Effort S, risk high. ✅ No change now. ✅ Revisit before Phase 5 docs. ❌ The plan's main promise is false for migrated installs.

State: approved
Actual answer: A) Apply: honest claim + cleanup (D24, 2026-10-25)
Accepted scope: the claim covers a migrated install only after old copies are destroyed, with a docs checklist (old backups, cred bundles, S3 bundle object versions, `cluster.env` history); `scripts/sandboxd-backup.sh` stops archiving the plaintext key line and key file and keeps the wrapped file; `sandboxd key status` shows "migrated from plaintext" until `sandboxd key ack-migration`; server-key rotation stays a non-goal (TODO asked separately); the claim, §3, §9 and tests updated.
History: none

### OV6: a hung PKCS#11 helper
Finding: outside voice OV6, Medium, confidence 8/10, Design §2 "Process (eng D5) ... If the helper exits, sandboxd restarts it", reviewer: codex (verified by eng review)
Plan baseline: eng D5 (approved B): sandboxd restarts the helper **on exit** with backoff
Runtime evidence: a vendor `C_Encrypt`/`C_Decrypt` can block inside the helper while the process stays alive; the caller's context cancels only sandboxd's wait, not the vendor call, so the session stays held; enough hangs exhaust the pool (MAX_INFLIGHT + 2, eng D13) and stall the `key_custody` loop (eng D2)
Comparison grid:

```text
Commitment                         | Current (D5)               | A (apply: deadlines + replace)              | B (keep)           | C (investigate) | D (defer)
per-op deadline in the helper       | none                       | each op carries a deadline (default 5 s,    | none               | none            | none
                                   |                            | constant)                                   |                    |                 |
helper with an op past its deadline| keeps running              | sandboxd kills and replaces it; in-flight   | keeps running      | same            | same
                                   |                            | calls get ErrProviderUnavailable            |                    |                 |
sessions held by a hung call       | held until it returns      | released by process death                   | held               | same            | same
key_custody loop under a hang      | can stall                  | each step has its own deadline, so the loop | can stall          | same            | same
                                   |                            | moves on to the next tick                   |                    |                 |
metric                             | none                       | aerolvm_pkcs11_helper_restarts_total{reason}| none               | none            | none
                                   |                            | (exit, deadline)                            |                    |                 |
effort                             | n/a                        | S (human ~1d / CC ~1h)                      | S                  | S               | S
```

Question D25:
D25 — OV6: If the HSM helper hangs instead of crashing, how do we recover?
Project: plans/customer-key-custody on PR #784; outside voice finding OV6 (Medium).
ELI10: D5 put the HSM library in a helper process that sandboxd restarts if it crashes. But a vendor library can also just hang: the helper stays alive and never answers, holding HSM sessions. Enough hangs use up every session, and the background key loop stalls too. Giving every request a time limit, and replacing a helper that blows it, turns a hang into the same quick recovery as a crash.
Stakes if we pick wrong: a hanging vendor library can freeze all key work on a node until someone restarts it by hand.
Recommendation: A because a hang should recover the same way a crash does, and killing the helper is the only reliable way to free a vendor session stuck in a C call (thorough handling over speed).
Note: options differ in kind, not coverage — no completeness score.
Net: hangs recover like crashes, against hangs that need a human.
Header: Helper hangs
Options:
A) Apply: deadlines + replace
Every helper op carries a deadline (5 s, a constant); if any op passes it, sandboxd kills and replaces the helper and in-flight calls get `ErrProviderUnavailable`; each `key_custody` step runs under its own deadline so the loop reaches its next tick; a restart counter labels the reason (exit or deadline). Effort S (human ~1d / CC ~1h), risk low; tested with a fake helper that never answers. ✅ A hang costs one helper restart, like a crash. ✅ The key loop never stalls behind a vendor call. ❌ A slow but healthy HSM call past 5 s gets cut and retried as unavailable.
B) Keep D5 as is
Restart only on exit. Effort S, risk medium. ✅ No new timer logic. ✅ No risk of cutting a slow but valid call. ❌ A hung vendor call can hold sessions and stall key work until a manual restart.
C) Investigate first
Spend at most half a day measuring CloudHSM and SoftHSM call latency tails to pick a deadline; then ask again. Effort S (study only), risk medium. ✅ The deadline is set from data. ✅ No change yet. ❌ The hang path stays unhandled in the plan until then (Phase 0 measures latency anyway).
D) Defer
Keep D5 as is and leave OV6 open. Effort S, risk medium. ✅ No change now. ✅ Revisit in Phase 3. ❌ Phase 3 starts without a hang story.

State: approved
Actual answer: A) Apply: deadlines + replace (D25, 2026-10-30)
Accepted scope: every helper op carries a 5 s deadline (constant); an op past it makes sandboxd kill and replace the helper, and in-flight calls get `ErrProviderUnavailable`; each `key_custody` step runs under its own deadline; `aerolvm_pkcs11_helper_restarts_total{reason}` (exit, deadline); a test with a fake helper that never answers; §2, Section 8 metrics and tests updated.
History: none

### T-ROT: server-key (data key) rotation TODO
Finding: TODO proposal from D24 (outside voice OV5), reviewer: eng review (Claude)
Plan baseline: Non-goals: "Rotating the server key itself. The `Cipher` format has no key ID, so rotating the data key means resealing every row." D24 chose an honest claim plus a cleanup checklist and said this TODO would be asked separately
Runtime evidence: `Cipher` seals `nonce || ciphertext+tag` with no key id (`pkg/secrets/secrets.go:25-30`); every sealed column (env, toolbox tokens, registry, mounts, egress CA, local cluster copies) uses it
TODO draft:
- What: rotate the server key itself: give the `Cipher` format a key id, keep old keys decrypt-only, reseal every row on every node under the new key, then retire the old one.
- Why: after a migration from a plaintext key (D24), old backups and bundles still hold the key; rotating it makes them useless without a manual cleanup. Also meets data-key cryptoperiod rules.
- Pros: closes OV5 completely; a standard answer to "how do you rotate data keys?".
- Cons: a cross-node reseal of every sealed column; a format change with a dual-read period; large (XL).
- Context: start at `pkg/secrets/secrets.go` (`Cipher`, `loadOrGenerateKey`) and the store's sealed columns (`internal/store/store.go:2191-2213` for toolbox tokens); reuse the sweep's compare-and-swap pattern from Design §11.
- Effort: human XL / CC L. Priority: P3. Depends on: this plan's Phase 4 (wrapped server key) and Phase 4b (sweep).
Comparison grid:

```text
Commitment            | Current            | A (add to TODOS.md)            | B (skip)                     | C (build it now)
server-key rotation   | non-goal           | tracked TODO, P3               | not tracked                  | in this stack (XL)
OV5 old copies        | cleanup checklist  | cleanup checklist (D24)        | cleanup checklist (D24)      | old copies made useless
effort now            | n/a                | S (one TODOS.md entry)         | none                         | XL (human ~4w / CC ~3d)
```

Question D26:
D26 — T-ROT: Track rotating the server key itself as a TODO?
Project: plans/customer-key-custody on PR #784; a TODO that came out of D24.
ELI10: D24 made the promise honest for installs that migrate from a plain key: old backups still hold the key until someone destroys them. The full fix is to give the server key a version and re-encrypt everything under a new one, so old copies stop working. That is a large job across every node and every kind of stored secret, so the question is only whether to write it down as future work.
Stakes if we pick wrong: skipping it loses the only full fix for old copies; building it now adds the biggest piece of work in the whole plan.
Recommendation: A because it is the real fix for D24's limitation and a common audit question, but it is far too large to add to this stack.
Note: options differ in kind, not coverage — no completeness score.
Net: a tracked follow-up, against forgetting it or roughly doubling this stack.
Header: Key rotation TODO
Options:
A) Add to TODOS.md (recommended)
Add a P3 entry "Rotate the server key (data key)" with the What/Why/Pros/Cons/Start fields above, depending on Phases 4 and 4b. Effort S now (one entry). ✅ The full fix for old copies is recorded with where to start. ✅ Answers the "how do you rotate data keys?" audit question with a plan. ❌ One more open TODO in the backlog.
B) Skip
Do not record it; D24's checklist is the answer. Effort none. ✅ No backlog growth. ✅ Nothing to maintain. ❌ The only complete fix for old plaintext copies is forgotten.
C) Build it now
Add server-key rotation to this stack. Effort XL (human ~4w / CC ~3d), risk high. ✅ Old copies are useless after any migration. ✅ Data-key rotation ships with the feature. ❌ Roughly doubles the stack and adds a cross-node format change.

State: approved
Actual answer: C) Build it now (D26, 2026-10-30; against the "add to TODOS.md" recommendation)
Accepted scope: server-key rotation ships in this stack as Design §13 and Phase 4c: a key-id `Cipher` format with authenticated dual read, a key ring in the server-key file, a staged rotation (stage, promote, reseal, retire) gated on every member's gossip feature version and proved by gauges, and a reseal of every sealed column by the `key_custody` loop; the Non-goal is removed; no TODOS.md entry.
History: none

Required work recorded without its own row, each covered by an approved
contract: Scope Challenge finding 2 (Vault sweep decrypts and re-encrypts;
factual correction), finding 4 (release-matrix build in Phase 3; required
proof for CEO-1), Section 1 finding 2 (one wrapper instance per process;
required for CEO-1), Section 2 finding 3 (diagram refresh), outside voice OV7
(sentinels pass through envelope opening; required for CEO-A1 and CEO-E2).
D1 was the gstack upgrade prompt, an admin choice, not a remedy.

Approval readiness: PASS. Checked rows and answers: structure (D2, Smaller
arrangement); E4b (D3 → A, "which bytes" half superseded by D20); CEO-E2e
(D4 → A); E6 (D5 → B); E7 (D6 → A); CEO-E2b (D7 → A); E9 (D8 → A); E4 (D9 →
A, condition superseded by D22); E1 (D10 → A); E2 (D11 → A); CEO-E2a (D12 →
A); E5 (D13 → A); E10 (D14 → A); R-REG (D15 → A); E3 (D16 → A); E8 (D17 →
A); CEO-E2c (D18 → A); CEO-E4a (D19 → A); OV1 (D20 → A); OV2 (D21 → A); OV3
(D22 → A); OV4 (D23 → A); OV5 (D24 → A); OV6 (D25 → A); T-ROT (D26 → C).

### Eng review outputs

`PLAN_REALITY: phase=eng rows=7/7 missing=none unverified=3 verdict=complete`

#### NOT in scope

- GCP Cloud KMS and Azure Key Vault (CEO-E5, TODOS.md).
- HSM signing of audit heads (CEO-E6, TODOS.md).
- External → external provider switching (Non-goals; `local → external` is
  supported, eng D8/D22).
- A PKCS#11 key-wrap fallback for HSMs without AES-GCM, unless Phase 0 finds
  one (eng D16).
- Direct Vault login methods in sandboxd (eng D10).
- Placement changes on revoke (eng D7).
- Configurable limiter internals beyond `SB_SECRET_PROVIDER_MAX_INFLIGHT`
  (eng D13).

#### What already exists

The CEO "What already exists" table still holds. The eng review adds:

- the gateway's memory-only secrets (`internal/egress/snapshot.go:34`), so a
  restart clears them (D4, D21);
- the gossip feature-version gate (`liveMembersAtLeast`,
  `internal/cluster/audit_caller_gate.go:46`), reused to gate server-key
  rotation (D26);
- the `--wasm-worker` helper pattern (`cmd/sandboxd/main.go:39`), reused for
  `--pkcs11-helper` (D5);
- the identical-bytes skip in `PutClusterSecret` (`internal/store/store.go:5888`),
  extended by the envelope comparison (D3, D20);
- `refuseGroupOtherBits` extracted from `wrap_key_loader.go:72` (D14). Shared
  helper evidence: one existing caller and two proposed; about 4 lines saved
  net; one table test instead of three.

#### Diagrams

The eng review adds or refreshes:

- the system architecture (refreshed for D2, D5 and D6);
- the Section 3 coverage diagram;
- the Section 4 async schedule (sweep vs writers, CEO review);
- the server-key ring below.

Name inline diagrams in `internal/service/key_custody.go` (the loop's states)
and `pkg/secrets/secrets.go` (blob format).

```
SERVER-KEY RING (eng D26), per key
  [none] --stage--> DECRYPT --promote--> CURRENT --(next key promoted)--> DECRYPT
  DECRYPT --retire (rows on it = 0 on every member)--> RETIRED (bytes dropped)
  invariant: exactly one CURRENT; stage refused unless every member has the ring fv
  invalid: RETIRED -> anything (a retired key's bytes are gone)
```

#### Failure modes (new or changed by the eng review)

```
CODEPATH                   | FAILURE                                   | TEST? | HANDLED? | USER SEES
peer copy after a rewrap   | late older copy overwrites a newer one     | Y     | Y (D20)  | nothing; rotation holds
revoke, open inspected conn| keeps the old inspector, injects secrets   | Y     | Y (D21)  | inspected session closed; inject denied
revoke, old gateway        | unknown op keeps the CA                    | Y     | Y (D4)   | gateway restarted; alert says so
local -> awskms switch     | unswitched node cannot open AWS rows       | Y     | Y (D22)  | nothing; failover works
PKCS#11 label rotation     | peers reject rows on a new label           | Y     | Y (D23)  | nothing if the staged steps are followed
migration from plaintext   | old backups still decrypt                  | Y     | Y (D24/26)| custody report notice; rotation or cleanup
PKCS#11 helper hang        | sessions held, loop stalls                 | Y     | Y (D25)  | brief 503, helper replaced
server-key rotation        | old binary meets a key-id blob             | Y     | Y (fv gate)| stage refused until all members upgrade
cluster-secret open, revoked| sentinel folded into DecryptFailed (500)  | Y     | Y (OV7)  | 503 key_revoked
```

Critical gaps: 0 (the CEO review's one, CEO-E2e, closed by D4).

#### Worktree parallelization strategy

| Step | Modules touched | Depends on |
|---|---|---|
| Phase 1 seam, limiter, errors | `pkg/secrets/`, `pkg/api/apihttp/`, `internal/config/` | — |
| Phase 2 vault | `pkg/secrets/` (vault.go only) | Phase 1 |
| Phase 3 pkcs11 + helper | `pkg/secrets/pkcs11/`, `cmd/sandboxd/` | Phase 1 |
| Phase 4 wrapped key, loop, full stop | `pkg/daemon/`, `pkg/secrets/`, `internal/service/`, `internal/egress/`, `pkg/sshgateway/`, `cmd/sandboxd/`, `scripts/`, `Terraform/` | Phase 1 |
| Phase 4b sweep, migration, peer copies | `internal/service/`, `internal/store/`, `pkg/secrets/` | Phase 4 |
| Phase 4c server-key rotation | `pkg/secrets/`, `internal/service/`, `internal/store/`, `internal/cluster/` (fv read only), `cmd/sandboxd/` | Phase 4b |
| Phase 5 docs, alerts, dashboards | `docs/`, `setup/` | decisions (start now), finalize after 4c |
| Phase 6 CI and live itests | `.github/workflows/`, `integration-tests/` | Phases 2–4c |

- **Lane A:** Phase 1 → Phase 4 → Phase 4b → Phase 4c (shared `pkg/secrets/` and `internal/service/`).
- **Lane B:** Phase 2 (after Phase 1).
- **Lane C:** Phase 3 (after Phase 1).
- **Lane D:** Phase 5 drafts.
- **Execution order:** launch A; when Phase 1 lands on its branch, launch B and C alongside A; D runs throughout; Phase 6 waits for all. The stack still merges as a whole.
- **Conflict flags:** `cmd/sandboxd/main.go` is touched by Phase 3 (helper flag) and Phase 4 (`key` subcommand), so sequence those two edits. `pkg/secrets/factory.go` is touched by Phases 1, 2 and 3; land Phase 1 first.

## Implementation Tasks (eng review)

Synthesized from this review's findings. Each task derives from a specific
finding above. Ratios assumed: features ~30x, tests ~50x, architecture ~5x.

- [ ] **ET1 (P1, human: ~1d / CC: ~30min)** — store — compare envelopes without `WrappedKey`, keep existing bytes
  - Surfaced by: Scope Challenge finding 1; outside voice OV1 (D3, D20)
  - Files: `internal/store/store.go`, `pkg/secrets/envelope.go`
  - Verify: `go test ./internal/store/... -run ClusterSecret`
- [ ] **ET2 (P1, human: ~2h / CC: ~10min)** — envelope — pass `ErrKeyRevoked` and `ErrKeyVersionRetired` through
  - Surfaced by: outside voice OV7
  - Files: `pkg/secrets/envelope.go`
  - Verify: the provider-to-handler 503 test
- [ ] **ET3 (P1, human: ~2d / CC: ~2h)** — egress — full clear op, secret-free Syncs while revoked, old-gateway restart
  - Surfaced by: Section 1 finding 1; OV2 (D4, D21)
  - Files: `internal/egress/proto.go`, `internal/egress/server.go`, `internal/egress/gatewayd/daemon.go`, `internal/egress/proxy/inspect.go`, `internal/service/`
  - Verify: open keep-alive inspected connection across a revoke; fake old gateway
- [ ] **ET4 (P1, human: ~2w / CC: ~1d)** — pkcs11 — helper process with deadlines and replacement, own package
  - Surfaced by: Section 1 (D5, D6); OV6 (D25)
  - Files: `pkg/secrets/pkcs11/`, `cmd/sandboxd/main.go`
  - Verify: helper-exit and never-answers tests; SoftHSM2 CI job
- [ ] **ET5 (P1, human: ~1d / CC: ~1h)** — open rules — tagged rows by settings, untagged AWS by settings
  - Surfaced by: Section 1 (D8); OV3 (D22)
  - Files: `pkg/secrets/`
  - Verify: two-step switch tests for `vault` and `awskms`
- [ ] **ET6 (P1, human: ~1d / CC: ~1h)** — pkcs11 rotation — staged steps and info gauges
  - Surfaced by: OV4 (D23)
  - Files: `pkg/secrets/pkcs11/`, `internal/service/metrics.go`
  - Verify: SoftHSM2 four-step rotation UC
- [ ] **ET7 (P1, human: ~1d / CC: ~1h)** — backups — no plaintext key in backups; migration notice and ack
  - Surfaced by: OV5 (D24)
  - Files: `scripts/sandboxd-backup.sh`, `scripts/sandboxd-restore.sh`, `cmd/sandboxd/key.go`
  - Verify: backup-contents test; `key status` notice test
- [ ] **ET8 (P1, human: ~4w / CC: ~3d)** — server-key rotation — format, ring, staged commands, reseal, fv gate
  - Surfaced by: T-ROT (D26)
  - Files: `pkg/secrets/secrets.go`, `internal/service/key_custody.go`, `internal/store/store.go`, `cmd/sandboxd/key.go`
  - Verify: dual-read, fv-gate, reseal-race tests; live rotation UC
- [ ] **ET9 (P1, human: ~3h / CC: ~20min)** — limiter — one setting; one foreground retry of Unavailable
  - Surfaced by: Section 2 (D13); Section 4 (D17)
  - Files: `pkg/secrets/limited.go`, `internal/config/config.go`, `setup/config-defaults.md`
  - Verify: limiter table test
- [ ] **ET10 (P1, human: ~3d / CC: ~3h)** — key_custody loop — re-check 5m×3, revoke, auto-recover, hourly sweep
  - Surfaced by: D2, D12, D18, D19
  - Files: `internal/service/key_custody.go`
  - Verify: injectable-clock tests; live revoke-and-recover UC
- [ ] **ET11 (P2, human: ~1h / CC: ~10min)** — secrets — `refuseGroupOtherBits` helper
  - Surfaced by: Section 2 finding 2 (D14)
  - Files: `pkg/secrets/wrap_key_loader.go`, new helper
  - Verify: `wrap_key_loader_test.go` unchanged and green; helper table test
- [ ] **ET12 (P1, human: ~1d / CC: ~1h)** — tests — regression rows in existing tables
  - Surfaced by: Section 3 regression rule (D15)
  - Files: `pkg/secrets/awskms_test.go`, `pkg/api/apihttp/classify_test.go`, `internal/store/cluster_secret_put_outbox_test.go`, `pkg/secrets/wrap_key_loader_test.go`, `pkg/secrets/secrets_test.go`, `internal/config/config_test.go`
  - Verify: `make test`
- [ ] **ET13 (P2, human: ~2h / CC: ~15min)** — CI — build every `sandboxd` release-matrix target with the cgo dependency
  - Surfaced by: Scope Challenge finding 4
  - Files: `.github/workflows/`
  - Verify: the CI job passes on all targets

Tasks JSONL: written to the gstack project directory (see Completion summary).

#### Suppressed findings

None (no finding scored below 5).

#### Unresolved decisions that may bite you later

None in this review. The CEO review's 15 eng-owned items were all answered
here (D3–D19), and the only open items are Phase 0 measurements, which the
gate table lists with the phases they gate.

#### Completion summary

- Step 0: Scope Challenge — scope accepted as-is (smaller arrangement, D2)
- Reality rows: 7/7 applicable rows emitted (`PLAN_REALITY` complete), 3 unverified premises
- Architecture Review: 10 issues found (2 findings + 8 open choices, all resolved)
- Code Quality Review: 3 issues found
- Test Review: diagram produced, 1 gap identified (regression contract, D15)
- Performance Review: 5 issues found (3 resolved by decisions, 2 recorded)
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 1 item proposed to user (built now instead, D26)
- Failure modes: 0 critical gaps flagged
- Unresolved decisions: 0 in this review
- Outside voice: codex (gpt-6-astra), completed; 7 findings, 6 resolved by decisions D20–D25, 1 applied as required work
- Parallelization: 4 lanes, 3 parallel / 1 sequential (Lane A)
- Lake Score: N/A (no answers were scored for completeness)

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | ISSUES OPEN (2026-10-21; older than the 7-day window, see note) | 6 proposals, 4 accepted, 2 deferred |
| Outside Review | codex, from `/plan-ceo-review` and `/plan-eng-review` | Independent 2nd opinion | 2 | completed (eng phase); unavailable (CEO phase) | 7 findings; 7 resolved; 0 unresolved (eng phase). CEO phase: codex MODEL_UNUSABLE, native fallback timed out, no completed external review |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | ISSUES OPEN | 19 issues, 0 critical gaps (all dispositioned: D2–D26; 0 unresolved) |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — (no UI scope) |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

Note: the CEO review's 15 open items were all eng-owned and were answered in
this eng review (D3–D19); its log row predates them.

- **OUTSIDE COVERAGE:** codex (gpt-6-astra), eng plan-review phase, completed, 7 findings (OV1–OV7): six resolved by decisions D20–D25, one applied as required work (OV7). CEO plan-review phase: unavailable (MODEL_UNUSABLE; native fallback gave no report within five minutes).
- **CROSS-MODEL:** the native eng review (Claude) and codex agree on the core design. Codex found seven problems the native review had missed:
  - peer-copy overwrite after a rewrap;
  - inspected connections and injected secrets surviving a revoke;
  - the AWS KMS two-step switch;
  - PKCS#11 label rollout order;
  - plaintext keys in old backups;
  - helper hangs;
  - sentinels lost in envelope opening.

  Every one was confirmed against the code before acting. There was no disagreement left after the decisions.
- **VERDICT:** no review is CLEAR. The eng review ran and resolved every decision with 0 critical gaps, but its status is ISSUES OPEN because it found issues, and only a clean run clears the dashboard. Eng review required (a clean re-run, or the user's call to proceed to implementation).

NO UNRESOLVED DECISIONS
