//go:build cgo

package pkcs11

import (
	"errors"
	"fmt"
	"strings"

	p11 "github.com/miekg/pkcs11"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// gcmTagBits is the GCM tag length for every wrap.
const gcmTagBits = 128

// miekgHSM is hsmAPI on github.com/miekg/pkcs11, which dlopens the vendor
// module at run time, so nothing vendor-specific is linked at build time.
type miekgHSM struct{ ctx *p11.Ctx }

func openModule(path string) (hsmAPI, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("SB_SECRET_PKCS11_MODULE is required")
	}
	c := p11.New(path)
	if c == nil {
		return nil, fmt.Errorf("SB_SECRET_PKCS11_MODULE %s could not be loaded as a PKCS#11 library", path)
	}
	// miekg passes CKF_OS_LOCKING_OK: Go calls in from many OS threads.
	if err := c.Initialize(); err != nil && !isCode(err, p11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		c.Destroy()
		return nil, fmt.Errorf("%w: C_Initialize: %v", secrets.ErrProviderUnavailable, err)
	}
	return &miekgHSM{ctx: c}, nil
}

func (m *miekgHSM) slots() ([]slotInfo, error) {
	ids, err := m.ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}
	out := make([]slotInfo, 0, len(ids))
	for _, id := range ids {
		ti, err := m.ctx.GetTokenInfo(id)
		if err != nil {
			return nil, err
		}
		si, err := m.ctx.GetSlotInfo(id)
		if err != nil {
			return nil, err
		}
		out = append(out, slotInfo{
			ID:           id,
			Label:        strings.TrimRight(ti.Label, " \x00"),
			Hardware:     si.Flags&p11.CKF_HW_SLOT != 0,
			Manufacturer: strings.TrimRight(ti.ManufacturerID, " \x00"),
			Model:        strings.TrimRight(ti.Model, " \x00"),
		})
	}
	return out, nil
}

func (m *miekgHSM) openSession(slot uint) (p11.SessionHandle, error) {
	// Read-write: the IV probe creates and destroys a session key.
	return m.ctx.OpenSession(slot, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
}

func (m *miekgHSM) closeSession(sh p11.SessionHandle) { _ = m.ctx.CloseSession(sh) }

func (m *miekgHSM) loggedIn(sh p11.SessionHandle) (bool, error) {
	info, err := m.ctx.GetSessionInfo(sh)
	if err != nil {
		return false, err
	}
	return info.State == p11.CKS_RO_USER_FUNCTIONS || info.State == p11.CKS_RW_USER_FUNCTIONS, nil
}

func (m *miekgHSM) login(sh p11.SessionHandle, pin string) error {
	return m.ctx.Login(sh, p11.CKU_USER, pin)
}

func (m *miekgHSM) findKey(sh p11.SessionHandle, label string) (p11.ObjectHandle, bool, error) {
	if err := m.ctx.FindObjectsInit(sh, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}); err != nil {
		return 0, false, err
	}
	objs, _, err := m.ctx.FindObjects(sh, 2)
	if ferr := m.ctx.FindObjectsFinal(sh); err == nil {
		err = ferr
	}
	if err != nil {
		return 0, false, err
	}
	switch len(objs) {
	case 0:
		return 0, false, nil
	case 1:
		return objs[0], true, nil
	default:
		return 0, false, fmt.Errorf("%w: pkcs11 key label %q matches more than one key", secrets.ErrProviderUnavailable, label)
	}
}

func (m *miekgHSM) encryptGCM(sh p11.SessionHandle, key p11.ObjectHandle, iv, aad, pt []byte) ([]byte, []byte, error) {
	params := p11.NewGCMParams(iv, aad, gcmTagBits)
	defer params.Free()
	if err := m.ctx.EncryptInit(sh, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_GCM, params)}, key); err != nil {
		return nil, nil, err
	}
	ct, err := m.ctx.Encrypt(sh, pt)
	if err != nil {
		return nil, nil, err
	}
	// An HSM that picks its own IV (AWS CloudHSM) writes it back here.
	return ct, params.IV(), nil
}

func (m *miekgHSM) decryptGCM(sh p11.SessionHandle, key p11.ObjectHandle, iv, aad, ct []byte) ([]byte, error) {
	params := p11.NewGCMParams(iv, aad, gcmTagBits)
	defer params.Free()
	if err := m.ctx.DecryptInit(sh, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_GCM, params)}, key); err != nil {
		return nil, initError{err}
	}
	return m.ctx.Decrypt(sh, ct)
}

func (m *miekgHSM) newProbeKey(sh p11.SessionHandle) (p11.ObjectHandle, error) {
	return m.ctx.GenerateKey(sh, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_GEN, nil)}, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_VALUE_LEN, 32),
		p11.NewAttribute(p11.CKA_TOKEN, false),
		p11.NewAttribute(p11.CKA_ENCRYPT, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
	})
}

func (m *miekgHSM) destroy(sh p11.SessionHandle, obj p11.ObjectHandle) {
	_ = m.ctx.DestroyObject(sh, obj)
}

func (m *miekgHSM) close() {
	_ = m.ctx.Finalize()
	m.ctx.Destroy()
}
