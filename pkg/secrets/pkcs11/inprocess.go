package pkcs11

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// InProcess is the token used directly as a secrets.DataKeyWrapper, for the
// short-lived `sandboxd key` CLI: a vendor crash there only ends the command,
// so it needs no helper (§2). sandboxd itself always uses Helper.
type InProcess struct {
	b closingBackend
}

// OpenInProcess opens the token in this process.
func OpenInProcess(cfg TokenConfig) (*InProcess, error) {
	b, err := openBackend(cfg)
	if err != nil {
		return nil, err
	}
	return &InProcess{b: b}, nil
}

// Wrap implements secrets.DataKeyWrapper.
func (p *InProcess) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	return p.b.Wrap(ctx, dek, secrets.EncryptionContextAAD(encCtx))
}

// Unwrap implements secrets.DataKeyWrapper.
func (p *InProcess) Unwrap(ctx context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	return p.b.Unwrap(ctx, wrapped, secrets.EncryptionContextAAD(encCtx))
}

// Info is what the token reports.
func (p *InProcess) Info() Info { return p.b.Info() }

// Close closes the token.
func (p *InProcess) Close() { p.b.Close() }
