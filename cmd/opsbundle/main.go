// Command opsbundle writes aerolvm-ops-<version>.tar.gz, the release asset
// that carries the operator files from setup/ (plans/kubectl-style-cluster-
// ops.md §7, CEO D14): the Prometheus alert rules, the Alertmanager config,
// the Grafana dashboards and the runbooks. Before it, they were only in a
// checkout of the repo. release.yml runs it:
//
//	go run ./cmd/opsbundle -version "$VERSION" -o "dist/aerolvm-ops-${VERSION}.tar.gz"
//
// The file list is the tree itself, never a list kept by hand: every file
// under the four directories ships, except Go tests and their fixtures. A
// new dashboard or runbook ships the day it lands.
//
// The archive is reproducible: names sorted, owner root, fixed modes, and
// every time set to the -mtime (default $SOURCE_DATE_EPOCH, else 0), so
// the same tree gives the same bytes and the same checksums.txt line.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// opsDirs are the setup/ directories the bundle carries.
var opsDirs = []string{"prometheus", "alertmanager", "grafana", "runbooks"}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("opsbundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.String("version", getenv("VERSION"), "release tag (default $VERSION)")
	setup := fs.String("setup", "setup", "the setup/ directory to bundle")
	out := fs.String("o", "", "write the bundle here (default aerolvm-ops-<version>.tar.gz)")
	list := fs.Bool("list", false, "print the files the bundle would carry, and write nothing")
	mtime := fs.Int64("mtime", sourceDateEpoch(getenv), "the time every entry carries, in Unix seconds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "opsbundle: unexpected arguments %v\n", fs.Args())
		return 2
	}
	files, err := opsFiles(*setup)
	if err != nil {
		fmt.Fprintf(stderr, "opsbundle: %v\n", err)
		return 1
	}
	if *list {
		for _, f := range files {
			fmt.Fprintln(stdout, f)
		}
		return 0
	}
	if *version == "" {
		fmt.Fprintln(stderr, "opsbundle: -version (or $VERSION) is required")
		return 2
	}
	if *out == "" {
		*out = bundleName(*version)
	}
	data, err := build(*setup, *version, files, time.Unix(*mtime, 0).UTC())
	if err != nil {
		fmt.Fprintf(stderr, "opsbundle: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "opsbundle: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s: %d files\n", *out, len(files))
	return 0
}

// bundleName is the release asset's name.
func bundleName(version string) string { return "aerolvm-ops-" + version + ".tar.gz" }

func sourceDateEpoch(getenv func(string) string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(getenv("SOURCE_DATE_EPOCH")), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// opsFiles lists the files the bundle carries, relative to setup with
// forward slashes, sorted. A missing directory is an error: a rename in
// setup/ must not ship an empty bundle quietly.
func opsFiles(setup string) ([]string, error) {
	var files []string
	for _, dir := range opsDirs {
		root := filepath.Join(setup, dir)
		n := 0
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Test fixtures and hidden directories are not for operators.
				if p != root && (d.Name() == "fixtures" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || !ships(d.Name()) {
				return nil
			}
			rel, err := filepath.Rel(setup, p)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
			n++
			return nil
		})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, fmt.Errorf("%s has no files to ship", root)
		}
	}
	sort.Strings(files)
	return files, nil
}

// ships reports whether a file in an ops directory is for operators: Go
// files are the tree's own tests (alerts_test.go checks the rules).
func ships(name string) bool {
	return !strings.HasPrefix(name, ".") && !strings.HasSuffix(name, ".go")
}

// build writes the bundle: aerolvm-ops-<version>/<dir>/<file>, plus a
// VERSION file, as a reproducible tar.gz.
func build(setup, version string, files []string, mtime time.Time) ([]byte, error) {
	if len(files) == 0 {
		return nil, errors.New("no files to bundle")
	}
	top := strings.TrimSuffix(bundleName(version), ".tar.gz")
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.ModTime = mtime
	tw := tar.NewWriter(gz)
	dirs := map[string]bool{}
	dir := func(name string) error {
		if dirs[name] {
			return nil
		}
		dirs[name] = true
		return tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: mtime, Format: tar.FormatPAX})
	}
	file := func(name string, body []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
			ModTime: mtime, Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(body)
		return err
	}
	if err := dir(top); err != nil {
		return nil, err
	}
	if err := file(top+"/VERSION", []byte(version+"\n")); err != nil {
		return nil, err
	}
	for _, f := range files {
		body, err := os.ReadFile(filepath.Join(setup, filepath.FromSlash(f)))
		if err != nil {
			return nil, err
		}
		name := top + "/" + f
		for _, d := range parentDirs(name) {
			if err := dir(d); err != nil {
				return nil, err
			}
		}
		if err := file(name, body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// parentDirs lists the directories above name, outermost first.
func parentDirs(name string) []string {
	var out []string
	for d := path.Dir(name); d != "." && d != "/"; d = path.Dir(d) {
		out = append([]string{d}, out...)
	}
	return out
}
