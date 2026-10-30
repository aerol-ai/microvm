package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/secrets/pkcs11"
)

// keySubcommand is `sandboxd key`: the server-key custody tool
// (plans/customer-key-custody.md §3). It runs outside systemd, loads the
// env files the unit gives the daemon, calls the key store and never opens
// the database.
const keySubcommand = "key"

// defaultEnvFiles are the unit's EnvironmentFile entries, in order.
var defaultEnvFiles = []string{"/etc/sandboxd/sandboxd.env", "/etc/sandboxd/cluster.env"}

// keyCallTimeout bounds each key-store call the tool makes.
const keyCallTimeout = 30 * time.Second

// openKeyStore builds the key-store client for cfg; tests replace it. For
// pkcs11 the token opens in this process: a vendor crash only ends the
// command.
var openKeyStore = func(ctx context.Context, cfg config.Config) (secrets.DataKeyWrapper, func(), error) {
	if !secrets.IsExternalProvider(cfg.SecretProvider) {
		return nil, nil, errors.New("SB_SECRET_PROVIDER is local: wrapped custody needs awskms, vault or pkcs11")
	}
	var helper secrets.DataKeyWrapper
	closeFn := func() {}
	if cfg.SecretProvider == secrets.ProviderPKCS11 || cfg.PKCS11Configured() {
		tok, err := pkcs11.OpenInProcess(pkcs11.TokenConfig{
			Module: cfg.SecretPKCS11Module, TokenLabel: cfg.SecretPKCS11TokenLabel, PINFile: cfg.SecretPKCS11PINFile,
			KeyLabel: cfg.SecretPKCS11KeyLabel, DecryptLabels: cfg.SecretPKCS11DecryptLabels, IVMode: cfg.SecretPKCS11GCMIV, Sessions: 1,
		})
		if err != nil {
			return nil, nil, err
		}
		helper, closeFn = tok, tok.Close
	}
	w, err := secrets.NewWrapper(secrets.ContextWithBackgroundPurpose(ctx, "key-cli"), service.KeyStoreOptions(cfg, "key-cli", helper))
	if err != nil {
		closeFn()
		return nil, nil, err
	}
	return w, closeFn, nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

const keyUsage = `usage: sandboxd key <command> [--env-file PATH]...

  status [--check]      where each key lives; --check also unwraps the server-key file
  verify                unwrap the server-key file and check it, without the daemon
  wrap                  wrap the existing plaintext server key (migration)
  wrap --generate       make a new server key and write only the wrapped file
       [--seed]         (cluster mode: only on the seed, before its first boot)
  rewrap                re-wrap the server-key file under the key store's newest key
  unwrap --to-file --i-understand-plaintext
                        write the server key back to a plaintext file (rollback)
  ack-migration         acknowledge that old plaintext copies are destroyed
  rotate --stage        add a new server key, decrypt only (cluster: every member upgraded)
  rotate --promote      make the staged key current; nodes reseal their rows onto it
  rotate --retire ID    drop a key once no row on any member is left on it
`

// runKeyCLI runs `sandboxd key` with args after "key".
func runKeyCLI(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(out, keyUsage)
		if len(args) == 0 {
			return errors.New("missing command")
		}
		return nil
	}
	cmd := args[0]
	fs := flag.NewFlagSet("sandboxd key "+cmd, flag.ContinueOnError)
	fs.SetOutput(out)
	var envFiles stringList
	fs.Var(&envFiles, "env-file", "env file to load (repeatable; default /etc/sandboxd/sandboxd.env then cluster.env)")
	check := fs.Bool("check", false, "status: also unwrap the server-key file")
	generate := fs.Bool("generate", false, "wrap: make a new key instead of wrapping the plaintext one")
	seed := fs.Bool("seed", false, "wrap --generate in cluster mode: this node is the seed")
	toFile := fs.Bool("to-file", false, "unwrap: write the plaintext key file")
	understand := fs.Bool("i-understand-plaintext", false, "unwrap: acknowledge the key will sit in plaintext on disk")
	stage := fs.Bool("stage", false, "rotate: add a new decrypt-only key")
	promote := fs.Bool("promote", false, "rotate: make the staged key current")
	retire := fs.Int64("retire", -1, "rotate: retire this key id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(envFiles) == 0 {
		envFiles = defaultEnvFiles
	}
	for _, f := range envFiles {
		if err := loadEnvFile(f); err != nil {
			fmt.Fprintf(out, "warning: %v; using the process environment\n", err)
		}
	}
	cfg, err := config.LoadForKeyTool()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	ctx := context.Background()
	switch cmd {
	case "status":
		return keyStatus(ctx, cfg, *check, out)
	case "verify":
		return keyVerify(ctx, cfg, out)
	case "wrap":
		if *generate {
			return keyGenerate(ctx, cfg, *seed, out)
		}
		return keyWrap(ctx, cfg, out)
	case "rewrap":
		return keyRewrap(ctx, cfg, out)
	case "unwrap":
		if !*toFile || !*understand {
			return errors.New("unwrap writes the server key in plaintext and ends wrapped custody for this node; pass --to-file --i-understand-plaintext")
		}
		return keyUnwrap(ctx, cfg, out)
	case "ack-migration":
		return keyAckMigration(cfg, out)
	case "rotate":
		steps := 0
		step := ""
		for name, on := range map[string]bool{"stage": *stage, "promote": *promote, "retire": *retire >= 0} {
			if on {
				steps++
				step = name
			}
		}
		if steps != 1 {
			return errors.New("rotate takes exactly one of --stage, --promote or --retire ID")
		}
		if *retire > int64(^uint32(0)) {
			return fmt.Errorf("--retire %d is not a key id", *retire)
		}
		return keyRotate(ctx, cfg, step, uint32(max(*retire, 0)), out)
	default:
		fmt.Fprint(out, keyUsage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// loadEnvFile applies a systemd EnvironmentFile: KEY=VALUE lines, # and ;
// comments, optional quotes. A variable already in the process environment
// wins, as in the unit (the process env is on top).
func loadEnvFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("env file %s: %w", path, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if _, set := os.LookupEnv(k); !set {
			_ = os.Setenv(k, v)
		}
	}
	return sc.Err()
}

func withKeyStore(ctx context.Context, cfg config.Config, fn func(context.Context, secrets.DataKeyWrapper) error) error {
	w, closeFn, err := openKeyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(ctx, keyCallTimeout)
	defer cancel()
	return fn(ctx, w)
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func keyStatus(ctx context.Context, cfg config.Config, check bool, out io.Writer) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tWHERE IT LIVES\t")
	for _, row := range service.CustodyReport(cfg) {
		note := ""
		if !row.InScope {
			note = "(out of scope for key custody)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", row.Class, row.Custody, note)
	}
	_ = tw.Flush()
	if ring := cfg.KeyRingPath(); fileExists(ring) {
		if rf, err := secrets.ReadKeyRingFile(ring); err == nil {
			fmt.Fprintf(out, "\nserver-key ring file (plaintext): %s\n  keys: %s\n", ring, ringLines(rf.Ring))
		} else {
			fmt.Fprintf(out, "\nserver-key ring file: %v\n", err)
		}
	}
	path := cfg.CredentialKeyWrappedPath
	if !fileExists(path) {
		fmt.Fprintf(out, "\nwrapped server-key file: none at %s\n", path)
		if cfg.CredentialKeyCustody == secrets.CustodyWrapped {
			return fmt.Errorf("SB_CREDENTIAL_KEY_CUSTODY=wrapped but %s does not exist", path)
		}
		return nil
	}
	f, err := secrets.ReadWrappedKeyFile(path)
	if err != nil {
		return err
	}
	version := f.KeyVersion()
	if version == "" {
		version = "(the key store does not say)"
	}
	fmt.Fprintf(out, "\nwrapped server-key file: %s\n  provider: %s\n  key: %s\n  wrapped under: %s\n  server keys: %s\n", path, f.Provider, f.KeyRef, version, ringLines(f.Entries()))
	if f.MigratedFromPlaintext {
		fmt.Fprintln(out, "  migrated from plaintext: destroy old backups and bundles, then run `sandboxd key ack-migration`")
	}
	for _, p := range []struct{ what, path string }{{"plaintext key file", cfg.CredentialEncryptionKeyPath}} {
		if fileExists(p.path) {
			fmt.Fprintf(out, "  warning: a %s still exists at %s\n", p.what, p.path)
		}
	}
	if check {
		return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
			if _, err := secrets.UnwrapRing(ctx, w, f, nil); err != nil {
				return err
			}
			fmt.Fprintln(out, "  check: every server key unwraps and matches")
			return nil
		})
	}
	return nil
}

func keyVerify(ctx context.Context, cfg config.Config, out io.Writer) error {
	f, err := secrets.ReadWrappedKeyFile(cfg.CredentialKeyWrappedPath)
	if err != nil {
		return err
	}
	return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
		if _, err := secrets.UnwrapRing(ctx, w, f, nil); err != nil {
			return err
		}
		fmt.Fprintf(out, "ok: %s unwraps through %s and matches its check\n", cfg.CredentialKeyWrappedPath, f.Provider)
		return nil
	})
}

// writeVerified writes f and reads it back through the key store.
func writeVerified(ctx context.Context, w secrets.DataKeyWrapper, path string, f secrets.WrappedKeyFile, key []byte) error {
	if err := secrets.WriteWrappedKeyFile(path, f); err != nil {
		return err
	}
	back, err := secrets.ReadWrappedKeyFile(path)
	if err != nil {
		return err
	}
	got, err := secrets.UnwrapServerKey(ctx, w, back)
	if err != nil {
		return fmt.Errorf("verify %s: %w", path, err)
	}
	if key != nil && !bytes.Equal(got, key) {
		return fmt.Errorf("verify %s: it unwraps to a different key", path)
	}
	if _, err := secrets.UnwrapRing(ctx, w, back, nil); err != nil {
		return fmt.Errorf("verify %s: %w", path, err)
	}
	return nil
}

func keyWrap(ctx context.Context, cfg config.Config, out io.Writer) error {
	if ring := cfg.KeyRingPath(); fileExists(ring) {
		return keyWrapRing(ctx, cfg, ring, out)
	}
	key, ok, err := secrets.LoadPlaintextKey(cfg.CredentialEncryptionKey, cfg.CredentialEncryptionKeyPath)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no plaintext server key (SB_CREDENTIAL_ENCRYPTION_KEY or %s) to wrap; for a new install use `sandboxd key wrap --generate`", cfg.CredentialEncryptionKeyPath)
	}
	path := cfg.CredentialKeyWrappedPath
	return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
		if fileExists(path) {
			existing, err := secrets.ReadWrappedKeyFile(path)
			if err != nil {
				return err
			}
			got, err := secrets.UnwrapServerKey(ctx, w, existing)
			if err != nil {
				return fmt.Errorf("%s exists and does not unwrap: %w", path, err)
			}
			if !bytes.Equal(got, key) {
				return fmt.Errorf("%s already holds a different server key; refusing to replace it", path)
			}
			fmt.Fprintf(out, "already wrapped: %s holds this server key\n", path)
			return nil
		}
		f, err := secrets.WrapServerKey(ctx, w, key, secrets.NormalizeProviderName(cfg.SecretProvider), service.KeyStoreRef(cfg))
		if err != nil {
			return err
		}
		f.MigratedFromPlaintext = true
		if err := writeVerified(ctx, w, path, f, key); err != nil {
			return err
		}
		fmt.Fprintf(out, `wrapped: %s
next:
  1. copy %s to every node (it is ciphertext)
  2. set SB_CREDENTIAL_KEY_CUSTODY=wrapped and remove SB_CREDENTIAL_ENCRYPTION_KEY from the env files
  3. delete the plaintext key file %s (sandboxd does not delete it: secure delete on SSD and copy-on-write disks is not something it can promise)
  4. destroy old backups, cred bundles and S3 bundle object versions that hold the plaintext key, then run `+"`sandboxd key ack-migration`"+`
  5. restart node by node
`, path, path, cfg.CredentialEncryptionKeyPath)
		return nil
	})
}

// keyWrapRing migrates a rotated plaintext key: every live ring key is
// wrapped into a ring wrapped file.
func keyWrapRing(ctx context.Context, cfg config.Config, ringPath string, out io.Writer) error {
	ring, err := secrets.ReadKeyRingFile(ringPath)
	if err != nil {
		return err
	}
	path := cfg.CredentialKeyWrappedPath
	if fileExists(path) {
		return fmt.Errorf("refusing to replace the existing wrapped key %s", path)
	}
	return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
		f, err := secrets.WrapRing(ctx, w, ring, secrets.NormalizeProviderName(cfg.SecretProvider), service.KeyStoreRef(cfg))
		if err != nil {
			return err
		}
		f.MigratedFromPlaintext = true
		if err := writeVerified(ctx, w, path, f, nil); err != nil {
			return err
		}
		fmt.Fprintf(out, `wrapped: the server-key ring %s into %s
next: as for a single key (copy the wrapped file, set SB_CREDENTIAL_KEY_CUSTODY=wrapped, remove the env key), and also delete the plaintext ring file %s on every node
`, ringPath, path, ringPath)
		return nil
	})
}

func keyGenerate(ctx context.Context, cfg config.Config, seed bool, out io.Writer) error {
	path := cfg.CredentialKeyWrappedPath
	switch {
	case cfg.CredentialEncryptionKey != "":
		return errors.New("refusing to generate: SB_CREDENTIAL_ENCRYPTION_KEY is set (use `sandboxd key wrap` to wrap that key)")
	case fileExists(cfg.CredentialEncryptionKeyPath):
		return fmt.Errorf("refusing to generate: a plaintext key exists at %s (use `sandboxd key wrap`)", cfg.CredentialEncryptionKeyPath)
	case fileExists(path):
		return fmt.Errorf("refusing to generate: a wrapped key exists at %s", path)
	}
	if cfg.EnableCluster {
		// S5: a second key minted on a joiner would split the cluster.
		if !seed {
			return errors.New("refusing to generate in cluster mode without --seed: joiners copy the seed's wrapped file")
		}
		if entries, err := os.ReadDir(cfg.RaftDataDir); err == nil && len(entries) > 0 {
			return fmt.Errorf("refusing to generate: raft directory %s is not empty, so this node already joined a cluster", cfg.RaftDataDir)
		}
		if fileExists(cfg.DBPath) {
			return fmt.Errorf("refusing to generate: %s exists, so this node already ran", cfg.DBPath)
		}
	}
	key, err := secrets.NewServerKey()
	if err != nil {
		return err
	}
	return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
		f, err := secrets.WrapServerKey(ctx, w, key, secrets.NormalizeProviderName(cfg.SecretProvider), service.KeyStoreRef(cfg))
		if err != nil {
			return err
		}
		if err := writeVerified(ctx, w, path, f, key); err != nil {
			return err
		}
		fmt.Fprintf(out, "generated: %s (no plaintext copy was written)\n", path)
		return nil
	})
}

func keyRewrap(ctx context.Context, cfg config.Config, out io.Writer) error {
	path := cfg.CredentialKeyWrappedPath
	f, err := secrets.ReadWrappedKeyFile(path)
	if err != nil {
		return err
	}
	return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
		key, err := secrets.UnwrapServerKey(ctx, w, f)
		if err != nil {
			return err
		}
		nf, err := secrets.RewrapRing(ctx, w, f)
		if err != nil {
			return err
		}
		nf.Provider, nf.KeyRef = secrets.NormalizeProviderName(cfg.SecretProvider), service.KeyStoreRef(cfg)
		if err := writeVerified(ctx, w, path, nf, key); err != nil {
			return err
		}
		fmt.Fprintf(out, "rewrapped: %s, %s -> %s (rows rewrap in the daemon's sweep)\n", path, orUnknown(f.KeyVersion()), orUnknown(nf.KeyVersion()))
		return nil
	})
}

func orUnknown(v string) string {
	if v == "" {
		return "(unversioned)"
	}
	return v
}

// keyUnwrap is the rollback to custody=file (CEO-R1).
func keyUnwrap(ctx context.Context, cfg config.Config, out io.Writer) error {
	dst := cfg.CredentialEncryptionKeyPath
	if fileExists(dst) {
		return fmt.Errorf("refusing to overwrite the existing key file %s", dst)
	}
	f, err := secrets.ReadWrappedKeyFile(cfg.CredentialKeyWrappedPath)
	if err != nil {
		return err
	}
	if f.Format == secrets.WrappedKeyRingFormat {
		return keyUnwrapRing(ctx, cfg, f, out)
	}
	return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
		key, err := secrets.UnwrapServerKey(ctx, w, f)
		if err != nil {
			return err
		}
		fh, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
		_, werr := fh.Write([]byte(base64.StdEncoding.EncodeToString(key)))
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("write %s: %w", dst, werr)
		}
		fmt.Fprintf(out, `wrote the server key in plaintext to %s (mode 0600)
the key custody claim no longer holds for this node.
next: set SB_CREDENTIAL_KEY_CUSTODY=file and restart; the daemon records the change (key_custody_changed)
`, dst)
		return nil
	})
}

// keyUnwrapRing is the rollback of a rotated key: the plaintext ring file.
func keyUnwrapRing(ctx context.Context, cfg config.Config, f secrets.WrappedKeyFile, out io.Writer) error {
	dst := cfg.KeyRingPath()
	if fileExists(dst) {
		return fmt.Errorf("refusing to overwrite the existing ring file %s", dst)
	}
	return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
		ring, err := secrets.UnwrapRingToFile(ctx, w, f)
		if err != nil {
			return err
		}
		if err := secrets.WriteKeyRingFile(dst, ring); err != nil {
			return err
		}
		fmt.Fprintf(out, `wrote the server-key ring in plaintext to %s (mode 0600)
the key custody claim no longer holds for this node.
next: set SB_CREDENTIAL_KEY_CUSTODY=file and restart; the daemon records the change (key_custody_changed)
`, dst)
		return nil
	})
}

func keyAckMigration(cfg config.Config, out io.Writer) error {
	path := cfg.CredentialKeyWrappedPath
	f, err := secrets.ReadWrappedKeyFile(path)
	if err != nil {
		return err
	}
	if !f.MigratedFromPlaintext {
		fmt.Fprintln(out, "nothing to acknowledge: this key was never plaintext")
		return nil
	}
	f.MigratedFromPlaintext = false
	if err := secrets.WriteWrappedKeyFile(path, f); err != nil {
		return err
	}
	fmt.Fprintf(out, "acknowledged: %s no longer reports a plaintext migration; copy it to every node\n", path)
	return nil
}
