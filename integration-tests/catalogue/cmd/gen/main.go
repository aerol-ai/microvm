// Command gen renders reports/<scenario>-catalogue.md from catalogue JSON.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aerol-ai/microvm/integration-tests/catalogue"
)

func main() {
	var (
		scenario = flag.String("scenario", "", "scenario name (required)")
		inPath   = flag.String("in", "", "input catalogue JSON (required)")
		outDir   = flag.String("out", "reports", "output directory")
	)
	flag.Parse()
	if *scenario == "" || *inPath == "" {
		fmt.Fprintln(os.Stderr, "error: -scenario and -in are required")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	var doc catalogue.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}
	md := catalogue.RenderMarkdown(*scenario, doc)
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}
	outPath := filepath.Join(*outDir, *scenario+"-catalogue.md")
	if err := os.WriteFile(outPath, []byte(md), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d entries)\n", outPath, len(doc.Entries))
}
