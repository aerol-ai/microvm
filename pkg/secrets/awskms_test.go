package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
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
	encryptErr error
	decryptErr error
	plaintext  []byte
	ciphertext []byte
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
	got, err := a.Wrap(ctx, []byte("dek-bytes-32!!!!!!!!!!!!!!!!!"))
	if err != nil || string(got) != "wrapped" {
		t.Fatalf("Wrap = %q %v", got, err)
	}
	plain, err := a.Unwrap(ctx, []byte("wrapped"))
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

func TestAWSKMSNilClient(t *testing.T) {
	a := &AWSKMS{}
	if _, err := a.Wrap(context.Background(), []byte("x")); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Wrap nil = %v", err)
	}
	if _, err := a.Unwrap(context.Background(), []byte("x")); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Unwrap nil = %v", err)
	}
}
