// Command aerolvm-rootd-sign signs a built aerolvm-rootd for the runtime
// supervisor's signed swap (internal/rootswap; plans/security-gaps-m1-m4.md
// §3.3 "Upgrades", eng review D4), checks what it signed, and makes the
// release key. It runs where the release is built, never on a node.
//
//	aerolvm-rootd-sign -genkey <private key file>
//	    Makes a new release key: the private key goes to the file (PKCS#8
//	    PEM, mode 0600, never over an existing file), the public key to
//	    stdout, in the form internal/rootswap/release-keys.pub holds.
//
//	aerolvm-rootd-sign -key <private key file> -version <vX.Y.Z> <binary>...
//	    Signs each binary: writes <binary>.manifest and <binary>.sig next
//	    to it. -version is the release the binary was built as (its -X
//	    .../internal/version.Version). The platform comes from the binary's
//	    own build info and the API level from this tool's rootdpb, built
//	    from the same checkout. A binary for this machine is run with
//	    --version first, and signed only if it reports that version and
//	    API level. With -no-exec nothing is run: the release checks the
//	    version with -check-version in a step of its own, before the key
//	    exists, so no binary runs while the key is on disk or in the
//	    environment.
//
//	aerolvm-rootd-sign -check-version <vX.Y.Z> <binary>...
//	    The version check alone, with no key: each binary for this machine
//	    must report that version and this tool's API level.
//
//	aerolvm-rootd-sign -verify <public keys file> <binary>...
//	    Checks each binary against its manifest and signature, as the
//	    supervisor will, for the binary's own platform: the release's proof
//	    that the key it signed with is the one the runtime image trusts.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootswap"
)

// helperPath is the main package a signed binary must be built from: the
// tool signs the root helper and nothing else. Tests point it at others.
var helperPath = "github.com/aerol-ai/microvm/cmd/aerolvm-rootd"

// host is the platform this tool runs binaries for; tests change it to
// sign as for another machine.
var host = runtime.GOOS + "/" + runtime.GOARCH

func main() { os.Exit(mainCode(os.Args[1:], os.Stdout, os.Stderr)) }

const usageLine = "usage: aerolvm-rootd-sign -genkey <key file> | -key <key file> -version <vX.Y.Z> [-no-exec] <binary>... | -verify <public keys file> <binary>... | -check-version <vX.Y.Z> <binary>..."

func mainCode(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aerolvm-rootd-sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	genkey := fs.String("genkey", "", "make a release key: write the private key to this file and print the public key")
	keyFile := fs.String("key", "", "sign with the private key in this file (PKCS#8 PEM)")
	ver := fs.String("version", "", "the release version the binaries were built as")
	verify := fs.String("verify", "", "check the binaries against the public keys in this file")
	checkVer := fs.String("check-version", "", "check that the binaries report this release version, with no key")
	noExec := fs.Bool("no-exec", false, "sign without running the binaries (their version was checked with -check-version)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Exactly one mode; -no-exec goes with -key alone.
	modes := 0
	for _, v := range []string{*genkey, *keyFile, *verify, *checkVer} {
		if v != "" {
			modes++
		}
	}
	var err error
	switch {
	case modes != 1 || (*noExec && *keyFile == ""):
		fmt.Fprintln(stderr, usageLine)
		return 2
	case *genkey != "" && fs.NArg() == 0:
		err = genKey(*genkey, stdout)
	case *keyFile != "" && fs.NArg() > 0:
		err = signAll(*keyFile, *ver, *noExec, fs.Args(), stdout)
	case *verify != "" && fs.NArg() > 0:
		err = verifyAll(*verify, fs.Args(), stdout)
	case *checkVer != "" && fs.NArg() > 0:
		err = checkAll(*checkVer, fs.Args(), stdout)
	default:
		fmt.Fprintln(stderr, usageLine)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "aerolvm-rootd-sign:", err)
		return 1
	}
	return 0
}

// genKey writes a new private key to path, never over a file, and prints
// its public key.
func genKey(path string, stdout io.Writer) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	_, err = stdout.Write(rootswap.MarshalPublicKey(pub))
	return err
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: no PRIVATE KEY block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: a %T, want an ed25519 key", path, k)
	}
	return priv, nil
}

func signAll(keyFile, version string, noExec bool, binaries []string, stdout io.Writer) error {
	priv, err := readPrivateKey(keyFile)
	if err != nil {
		return err
	}
	for _, bin := range binaries {
		if err := signOne(priv, version, bin, noExec, stdout); err != nil {
			return fmt.Errorf("%s: %w", bin, err)
		}
	}
	return nil
}

// platform reads the binary's build info: it must be the helper, and its
// platform is the one it was built for.
func platform(bin string) (goos, goarch string, err error) {
	bi, err := buildinfo.ReadFile(bin)
	if err != nil {
		return "", "", err
	}
	if bi.Path != helperPath {
		return "", "", fmt.Errorf("built from %s, not %s", bi.Path, helperPath)
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "GOOS":
			goos = s.Value
		case "GOARCH":
			goarch = s.Value
		}
	}
	if goos == "" || goarch == "" {
		return "", "", errors.New("its build info names no platform")
	}
	return goos, goarch, nil
}

// checkAll is -check-version: the version check signOne makes, with no key.
func checkAll(version string, binaries []string, stdout io.Writer) error {
	for _, bin := range binaries {
		goos, goarch, err := platform(bin)
		if err == nil {
			err = checkVersion(bin, version, goos, goarch, stdout)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", bin, err)
		}
		fmt.Fprintf(stdout, "version ok %s: %s, API %d, %s/%s\n", bin, version, rootdpb.APIVersion, goos, goarch)
	}
	return nil
}

// checkVersion runs a binary for this machine with --version and refuses
// one that does not report version and this tool's API level. A binary for
// another platform cannot run here: its version is taken from -version.
func checkVersion(bin, version, goos, goarch string, stdout io.Writer) error {
	want := fmt.Sprintf("aerolvm-rootd %s (API %d)", version, rootdpb.APIVersion)
	if goos+"/"+goarch != host {
		fmt.Fprintf(stdout, "%s: a %s/%s binary cannot run here; its version is taken from -version\n", bin, goos, goarch)
		return nil
	}
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return fmt.Errorf("run --version: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		return fmt.Errorf("it reports %q; signing it as %q would misname it", got, want)
	}
	return nil
}

func signOne(priv ed25519.PrivateKey, version, bin string, noExec bool, stdout io.Writer) error {
	goos, goarch, err := platform(bin)
	if err != nil {
		return err
	}
	if noExec {
		fmt.Fprintf(stdout, "%s: not run (-no-exec); its version was checked before the key existed\n", bin)
	} else if err := checkVersion(bin, version, goos, goarch, stdout); err != nil {
		return err
	}
	f, err := os.Open(bin)
	if err != nil {
		return err
	}
	m, err := rootswap.NewManifest(f, version, rootdpb.APIVersion, goos, goarch)
	_ = f.Close()
	if err != nil {
		return err
	}
	manifest, sig, err := rootswap.Sign(priv, m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(bin+".manifest", manifest, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(bin+".sig", sig, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s: %s, API %d, %s/%s, %d bytes, sha256 %s\n", bin, m.Version, m.API, m.OS, m.Arch, m.Size, m.SHA256)
	return nil
}

func verifyAll(keysFile string, binaries []string, stdout io.Writer) error {
	raw, err := os.ReadFile(keysFile)
	if err != nil {
		return err
	}
	keys, err := rootswap.ParseKeys(raw)
	if err != nil {
		return err
	}
	for _, bin := range binaries {
		if err := verifyOne(keys, bin, stdout); err != nil {
			return fmt.Errorf("%s: %w", bin, err)
		}
	}
	return nil
}

func verifyOne(keys []ed25519.PublicKey, bin string, stdout io.Writer) error {
	goos, goarch, err := platform(bin)
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(bin + ".manifest")
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(bin + ".sig")
	if err != nil {
		return err
	}
	m, err := rootswap.VerifyFor(keys, manifest, sig, goos, goarch)
	if err != nil {
		return err
	}
	f, err := os.Open(bin)
	if err != nil {
		return err
	}
	got, err := rootswap.NewManifest(f, m.Version, m.API, goos, goarch)
	_ = f.Close()
	if err != nil {
		return err
	}
	if got != m {
		return fmt.Errorf("the binary is %d bytes, sha256 %s; the signed manifest says %d bytes, sha256 %s", got.Size, got.SHA256, m.Size, m.SHA256)
	}
	fmt.Fprintf(stdout, "ok %s: %s, API %d, %s/%s\n", bin, m.Version, m.API, m.OS, m.Arch)
	return nil
}
