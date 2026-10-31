package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

type stubAPIError struct {
	code string
}

func (e stubAPIError) Error() string                 { return e.code }
func (e stubAPIError) ErrorCode() string             { return e.code }
func (e stubAPIError) ErrorMessage() string          { return e.code }
func (e stubAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }

type stubKMS struct {
	encryptErr  error
	decryptErr  error
	describeErr error
	keyState    types.KeyState
	plaintext   []byte
	ciphertext  []byte
}

func (s *stubKMS) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if s.describeErr != nil {
		return nil, s.describeErr
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{KeyState: s.keyState}}, nil
}

func (s *stubKMS) Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if s.encryptErr != nil {
		return nil, s.encryptErr
	}
	return &kms.EncryptOutput{CiphertextBlob: s.ciphertext}, nil
}

func (s *stubKMS) Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if s.decryptErr != nil {
		return nil, s.decryptErr
	}
	return &kms.DecryptOutput{Plaintext: s.plaintext}, nil
}

func TestAWSKMSWrapUnwrapStub(t *testing.T) {
	ctx := context.Background()
	stub := &stubKMS{ciphertext: []byte("wrapped"), plaintext: []byte("dek-bytes-32!!!!!!!!!!!!!!!!!")}
	a := NewAWSKMSWithClient(stub, "alias/test")
	got, err := a.Wrap(ctx, []byte("dek-bytes-32!!!!!!!!!!!!!!!!!"), nil)
	if err != nil || string(got) != "wrapped" {
		t.Fatalf("Wrap = %q %v", got, err)
	}
	plain, err := a.Unwrap(ctx, []byte("wrapped"), nil)
	if err != nil || string(plain) != "dek-bytes-32!!!!!!!!!!!!!!!!!" {
		t.Fatalf("Unwrap = %q %v", plain, err)
	}
}

func TestMapAWSKMSError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"throttle", stubAPIError{code: "ThrottlingException"}, ErrProviderThrottled},
		{"deny", stubAPIError{code: "AccessDeniedException"}, ErrProviderDenied},
		{"unavailable", stubAPIError{code: "KeyUnavailableException"}, ErrProviderUnavailable},
		{"other", errors.New("network"), ErrProviderUnavailable},
		// Intended differences (plans/customer-key-custody.md, eng D15): a
		// disabled or deleted key is a deliberate revoke. Before key custody
		// these mapped to unavailable and denied.
		{"disabled code", stubAPIError{code: "DisabledException"}, ErrKeyRevoked},
		{"not found code", stubAPIError{code: "NotFoundException"}, ErrKeyRevoked},
		// KMSInvalidStateException needs the key state; without it, unavailable.
		{"invalid state code", stubAPIError{code: "KMSInvalidStateException"}, ErrProviderUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapAWSKMSError(tc.err)
			if !errors.Is(got, tc.want) {
				t.Fatalf("mapAWSKMSError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
	if mapAWSKMSError(nil) != nil {
		t.Fatal("nil should stay nil")
	}
}

// KMSInvalidStateException is a revoke only when DescribeKey says the key is
// pending deletion; a disconnected custom key store or a failed DescribeKey is
// an outage (plans/customer-key-custody.md §10).
func TestAWSKMSInvalidStateClassification(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		state       types.KeyState
		describeErr error
		want        error
	}{
		{"pending deletion", &types.KMSInvalidStateException{}, types.KeyStatePendingDeletion, nil, ErrKeyRevoked},
		{"pending deletion via code", stubAPIError{code: "KMSInvalidStateException"}, types.KeyStatePendingDeletion, nil, ErrKeyRevoked},
		{"disconnected key store", &types.KMSInvalidStateException{}, types.KeyStateUnavailable, nil, ErrProviderUnavailable},
		{"enabled", &types.KMSInvalidStateException{}, types.KeyStateEnabled, nil, ErrProviderUnavailable},
		{"describe fails", &types.KMSInvalidStateException{}, "", errors.New("timeout"), ErrProviderUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubKMS{encryptErr: tc.err, decryptErr: tc.err, keyState: tc.state, describeErr: tc.describeErr}
			a := NewAWSKMSWithClient(stub, "alias/test")
			if _, err := a.Wrap(context.Background(), []byte("dek"), nil); !errors.Is(err, tc.want) {
				t.Fatalf("Wrap = %v, want %v", err, tc.want)
			}
			if _, err := a.Unwrap(context.Background(), []byte("w"), nil); !errors.Is(err, tc.want) {
				t.Fatalf("Unwrap = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAWSKMSNilClient(t *testing.T) {
	a := &AWSKMS{}
	if _, err := a.Wrap(context.Background(), []byte("x"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Wrap nil = %v", err)
	}
	if _, err := a.Unwrap(context.Background(), []byte("x"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Unwrap nil = %v", err)
	}
}
