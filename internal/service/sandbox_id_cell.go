package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"expvar"
	"fmt"
	"io"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Cells in sandbox IDs (plans/kubernetes-v2-architecture.md §12.3-12.4, C12
// and C16). A federation of cells shares one key (SB_CELL_ID_KEY), and a new
// ID's first byte is its cell masked with a byte of HMAC(key, the rest of
// the ID): every cell reads any ID's cell without a lookup, and no one
// without the key can, so an ID does not show how AerolVM is laid out.
// Without a key there is one cell and nothing to route, and the first byte
// is random like the rest.
//
// A request that reaches the wrong cell is not forwarded (cells do not
// trust each other): OtherCellEndpoint names the right cell's address, the
// API answers 421 with it, and the SDKs send the request there.

// cellIDMaskInfo is the HMAC's domain label, so the key means nothing to
// any other use of it.
const cellIDMaskInfo = "aerolvm-cell-id/v1"

func cellIDMask(key, rest []byte) byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(cellIDMaskInfo))
	m.Write(rest)
	return m.Sum(nil)[0]
}

// newSandboxIDInCell mints "sb-" and 16 hex digits: 8 random bytes, the
// first replaced by the masked cell when there is a key. A zero cell (a
// Config not built by config.Load, as in tests) is cell 1, the default.
func newSandboxIDInCell(cell int, key []byte) (string, error) {
	if cell == 0 {
		cell = 1
	}
	if cell < 1 || cell > 255 {
		return "", fmt.Errorf("sandbox id: cell %d is outside 1 to 255", cell)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	if len(key) > 0 {
		buf[0] = byte(cell) ^ cellIDMask(key, buf[1:])
	}
	return "sb-" + hex.EncodeToString(buf), nil
}

// IDInCell gives an ID derived from something else (an Idempotency-Key
// create's digest of owner and key) this cell's masked byte in front, so a
// retry still gets the same ID and the ID still says where it lives: the
// SDKs send a key with every create. Without a cell key, or for an ID of
// another shape, it returns id as it is.
func (s *Service) IDInCell(id string) string {
	if s == nil || len(s.cfg.CellIDKey) == 0 || !models.IsGeneratedSandboxID(id) {
		return id
	}
	raw := generatedIDBytes(id)
	raw[0] = byte(max(s.cfg.CellID, 1)) ^ cellIDMask(s.cfg.CellIDKey, raw[1:])
	return "sb-" + hex.EncodeToString(raw)
}

// generatedIDBytes is a generated ID's 8 bytes. The caller has checked the
// shape (models.IsGeneratedSandboxID: "sb-" and 16 lowercase hex digits),
// so the decode cannot fail.
func generatedIDBytes(id string) []byte {
	raw, _ := hex.DecodeString(strings.TrimPrefix(id, "sb-"))
	return raw
}

// sandboxIDCell reads the cell a generated ID was minted in. ok is false
// without a key, for anything but a generated ID, and for an ID whose byte
// unmasks to 0 (no cell; one minted without the key, say).
func sandboxIDCell(id string, key []byte) (int, bool) {
	if len(key) == 0 || !models.IsGeneratedSandboxID(id) {
		return 0, false
	}
	raw := generatedIDBytes(id)
	cell := int(raw[0] ^ cellIDMask(key, raw[1:]))
	return cell, cell != 0
}

// OtherCellEndpoint is the public address of the cell id belongs to, when
// that is another cell this one knows (SB_CELL_ENDPOINTS) and this node has
// no sandbox by that id: the request belongs there. The router calls it only
// for an id its own cell does not know. An id minted before the key, or
// derived from a key, can unmask to any cell; the local check keeps one that
// lives here served here, and every cell unmasks an id the same way, so a
// wrong guess ends in one cell's 404, never in a loop.
func (s *Service) OtherCellEndpoint(ctx context.Context, id string) (string, bool) {
	cell, ok := sandboxIDCell(strings.TrimSpace(id), s.cfg.CellIDKey)
	if !ok || cell == max(s.cfg.CellID, 1) {
		return "", false
	}
	endpoint := s.cfg.CellEndpoints[cell]
	if endpoint == "" || s.HasLocalSandbox(ctx, id) {
		return "", false
	}
	return endpoint, true
}

// cellRedirectsTotal counts requests answered 421 with another cell's
// address. A steady rate means clients reach sandboxes through the wrong
// cell: an SDK too old to follow the answer, or one not caching it.
var cellRedirectsTotal = expvar.NewInt("aerolvm_cell_redirects_total")

// RecordCellRedirect counts one such answer; the router calls it.
func RecordCellRedirect() { cellRedirectsTotal.Add(1) }
