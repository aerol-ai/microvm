package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

type config struct {
	apiURL, token  string
	concurrency    int
	duration       time.Duration
	image, runtime string
	template       string
	hold           bool
	maxAge         time.Duration
	createTimeout  time.Duration
	json           bool
	runID          string
	cleanupRun     string
}

// maxAgeSlack is how long after the run a sandbox it made deletes itself
// by default: the run's own cleanup has finished long before.
const maxAgeSlack = 15 * time.Minute

const maxConcurrency = 1000

// runIDPattern keeps a run id usable in a sandbox name and a tag value.
var runIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func parseFlags(args []string, stderr io.Writer) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("aerolvm-bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.apiURL, "api", os.Getenv("SB_API_URL"), "AerolVM API URL (default $SB_API_URL, else http://127.0.0.1:21212)")
	fs.StringVar(&cfg.token, "token", "", "API token (default $SB_PAT_TOKEN, else $SB_API_TOKEN)")
	fs.IntVar(&cfg.concurrency, "concurrency", 4, "creates in flight at once (each worker starts its next create when the last one answers)")
	fs.DurationVar(&cfg.duration, "duration", 30*time.Second, "how long to keep starting creates")
	fs.StringVar(&cfg.image, "image", "alpine:3.20", "image of every sandbox")
	fs.StringVar(&cfg.runtime, "runtime", "", "runtime of every sandbox: docker, gvisor, firecracker, ... (default: the server's)")
	fs.StringVar(&cfg.template, "template", "", "Firecracker template every sandbox starts from (pass the image it was built from as -image); without one, each Firecracker create builds its disk from the image")
	fs.BoolVar(&cfg.hold, "hold", false, "keep every sandbox until the run ends, then delete them all (default: delete each one in the background as soon as it exists)")
	fs.DurationVar(&cfg.maxAge, "max-age", 0, "each sandbox deletes itself at this age even if the tool is killed (default: the run length plus -create-timeout plus 15m; 0s: off)")
	fs.DurationVar(&cfg.createTimeout, "create-timeout", 5*time.Minute, "give up on one create after this long")
	fs.BoolVar(&cfg.json, "json", false, "print the report as JSON")
	fs.StringVar(&cfg.runID, "run-id", "", "id that names and tags this run's sandboxes (default: random)")
	fs.StringVar(&cfg.cleanupRun, "cleanup", "", "delete every sandbox an earlier run left, by its run id, and exit")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if cfg.token == "" {
		cfg.token = firstEnv("SB_PAT_TOKEN", "SB_API_TOKEN")
	}
	if cfg.token == "" {
		return cfg, errors.New("a token is required: -token, SB_PAT_TOKEN or SB_API_TOKEN")
	}
	if cfg.cleanupRun != "" {
		if !runIDPattern.MatchString(cfg.cleanupRun) {
			return cfg, fmt.Errorf("-cleanup %q is not a run id", cfg.cleanupRun)
		}
		return cfg, nil
	}
	switch {
	case cfg.concurrency < 1 || cfg.concurrency > maxConcurrency:
		return cfg, fmt.Errorf("-concurrency must be between 1 and %d", maxConcurrency)
	case cfg.duration <= 0:
		return cfg, errors.New("-duration must be more than 0")
	case cfg.createTimeout <= 0:
		return cfg, errors.New("-create-timeout must be more than 0")
	case cfg.maxAge < 0:
		return cfg, errors.New("-max-age must not be negative")
	case strings.TrimSpace(cfg.image) == "":
		return cfg, errors.New("-image is required")
	}
	if !set["max-age"] {
		cfg.maxAge = cfg.duration + cfg.createTimeout + maxAgeSlack
	}
	if cfg.runID == "" {
		cfg.runID = newRunID()
	} else if !runIDPattern.MatchString(cfg.runID) {
		return cfg, fmt.Errorf("-run-id %q: use 1 to 32 lowercase letters, digits and dashes", cfg.runID)
	}
	return cfg, nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func newRunID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
