package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

// kmsAPI is the subset of the AWS KMS client used by AWSKMS. Narrowed for tests.
type kmsAPI interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// AWSKMS wraps DEKs with AWS KMS Encrypt/Decrypt. Ciphertext still lives in
// BlobStore; this only custodians the data key.
type AWSKMS struct {
	client kmsAPI
	keyID  string
}

// NewAWSKMS builds an AWSKMS from the default AWS config chain (env, shared
// config, IAM role). keyID is the CMK id/arn/alias (SB_SECRET_AWS_KMS_KEY_ID).
func NewAWSKMS(ctx context.Context, keyID string) (*AWSKMS, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, fmt.Errorf("SB_SECRET_AWS_KMS_KEY_ID is required when SB_SECRET_PROVIDER=awskms")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: load aws config: %v", ErrProviderUnavailable, err)
	}
	return &AWSKMS{client: kms.NewFromConfig(cfg), keyID: keyID}, nil
}

// NewAWSKMSWithClient is for tests that inject a fake kmsAPI.
func NewAWSKMSWithClient(client kmsAPI, keyID string) *AWSKMS {
	return &AWSKMS{client: client, keyID: strings.TrimSpace(keyID)}
}

// Wrap implements DataKeyWrapper via KMS Encrypt.
func (a *AWSKMS) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	if a == nil || a.client == nil {
		return nil, fmt.Errorf("%w: aws kms client is not configured", ErrProviderUnavailable)
	}
	in := &kms.EncryptInput{
		KeyId:     aws.String(a.keyID),
		Plaintext: dek,
	}
	if len(encCtx) > 0 {
		in.EncryptionContext = encCtx
	}
	out, err := a.client.Encrypt(ctx, in)
	if err != nil {
		return nil, mapAWSKMSError(err)
	}
	if out == nil || len(out.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("%w: aws kms encrypt returned empty ciphertext", ErrProviderUnavailable)
	}
	return out.CiphertextBlob, nil
}

// Unwrap implements DataKeyWrapper via KMS Decrypt.
func (a *AWSKMS) Unwrap(ctx context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	if a == nil || a.client == nil {
		return nil, fmt.Errorf("%w: aws kms client is not configured", ErrProviderUnavailable)
	}
	in := &kms.DecryptInput{
		CiphertextBlob: wrapped,
		KeyId:          aws.String(a.keyID),
	}
	if len(encCtx) > 0 {
		in.EncryptionContext = encCtx
	}
	out, err := a.client.Decrypt(ctx, in)
	if err != nil {
		return nil, mapAWSKMSError(err)
	}
	if out == nil || len(out.Plaintext) == 0 {
		return nil, fmt.Errorf("%w: aws kms decrypt returned empty plaintext", ErrProviderUnavailable)
	}
	return out.Plaintext, nil
}

func mapAWSKMSError(err error) error {
	if err == nil {
		return nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException":
			return fmt.Errorf("%w: %v", ErrProviderThrottled, err)
		case "AccessDeniedException", "UnauthorizedOperation", "NotAuthorizedException":
			return fmt.Errorf("%w: %v", ErrProviderDenied, err)
		case "DisabledException", "KMSInvalidStateException", "KeyUnavailableException":
			return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
		}
	}
	var notFound *types.NotFoundException
	if errors.As(err, &notFound) {
		return fmt.Errorf("%w: %v", ErrProviderDenied, err)
	}
	var disabled *types.DisabledException
	if errors.As(err, &disabled) {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
}
