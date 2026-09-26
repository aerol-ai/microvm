package service

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractTemplateArtifactsErrorArmsWave15(t *testing.T) {
	dir := t.TempDir()

	// Truncated tar.
	if _, err := extractTemplateArtifactsFromLayer(strings.NewReader("not-a-tar"), dir); err == nil {
		t.Fatal("expected truncated tar error")
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: templateManifestFilename, Mode: 0o644, Size: 3})
	_, _ = tw.Write([]byte("{x}"))
	_ = tw.Close()
	if _, err := extractTemplateArtifactsFromLayer(bytes.NewReader(buf.Bytes()), dir); err == nil {
		t.Fatal("expected bad manifest json")
	}

	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	manifest := TemplateArtifactManifest{SchemaVersion: 1}
	mb, _ := json.Marshal(manifest)
	_ = tw2.WriteHeader(&tar.Header{Name: templateManifestFilename, Mode: 0o644, Size: int64(len(mb))})
	_, _ = tw2.Write(mb)
	_ = tw2.Close()
	if _, err := extractTemplateArtifactsFromLayer(bytes.NewReader(buf2.Bytes()), dir); err == nil {
		t.Fatal("expected missing artifacts")
	}

	if _, err := extractTemplateArtifactsFromSave(strings.NewReader("x"), dir); err == nil {
		t.Fatal("expected save extract fail")
	}
}
