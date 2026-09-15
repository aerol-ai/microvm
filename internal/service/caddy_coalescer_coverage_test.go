package service

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestCaddyCoalescerAndSecretsEntropyWave24(t *testing.T) {
	svc := &Service{cipher: newTestCipher(t), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	binding := secrets.SealBinding{SandboxID: "sb", IncarnationID: "inc-test", Ref: secrets.FormatRef("sb", "inc-test", 1), Version: 1, Generation: 1}
	bag := secrets.Secrets{Registry: &models.RegistryAuth{Username: "u", Password: "p"}}
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("dek")}})
	_, _ = secrets.SealEnvelopeBound(svc.cipher, bag, []string{"node-a"}, binding)
	setRandReader(t, &scriptedRandReader{errs: []error{nil, errors.New("nonce")}})
	_, _ = secrets.SealEnvelopeBound(svc.cipher, bag, []string{"node-a"}, binding)
}
