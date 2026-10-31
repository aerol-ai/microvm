package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// describeKeyTimeout bounds the extra call that tells a pending deletion from
// an outage; it must not stretch a failing create much past the KMS error.
const describeKeyTimeout = 2 * time.Second

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
		return nil, a.classify(ctx, err)
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
		return nil, a.classify(ctx, err)
	}
	if out == nil || len(out.Plaintext) == 0 {
		return nil, fmt.Errorf("%w: aws kms decrypt returned empty plaintext", ErrProviderUnavailable)
	}
	return out.Plaintext, nil
}

// classify maps a KMS error to a provider class. KMSInvalidStateException
// covers both a key pending deletion (a deliberate revoke) and states such as
// a disconnected custom key store (an outage), so it costs one DescribeKey to
// tell them apart (plans/customer-key-custody.md §10). Only PendingDeletion
// counts as a revoke; anything else, including a failed DescribeKey, stays
// unavailable.
func (a *AWSKMS) classify(ctx context.Context, err error) error {
	if !isInvalidState(err) {
		return mapAWSKMSError(err)
	}
	dctx, cancel := context.WithTimeout(ctx, describeKeyTimeout)
	defer cancel()
	out, derr := a.client.DescribeKey(dctx, &kms.DescribeKeyInput{KeyId: aws.String(a.keyID)})
	if derr == nil && out != nil && out.KeyMetadata != nil && out.KeyMetadata.KeyState == types.KeyStatePendingDeletion {
		return fmt.Errorf("%w: %v", ErrKeyRevoked, err)
	}
	return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
}

func isInvalidState(err error) bool {
	var invalid *types.KMSInvalidStateException
	if errors.As(err, &invalid) {
		return true
	}
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "KMSInvalidStateException"
}

// mapAWSKMSError maps every KMS error except KMSInvalidStateException, which
// needs the key's state (see classify). A disabled or deleted key is a
// deliberate revoke; before key custody both mapped to unavailable/denied.
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
		case "DisabledException", "NotFoundException":
			return fmt.Errorf("%w: %v", ErrKeyRevoked, err)
		case "KMSInvalidStateException", "KeyUnavailableException":
			return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
		}
	}
	var notFound *types.NotFoundException
	if errors.As(err, &notFound) {
		return fmt.Errorf("%w: %v", ErrKeyRevoked, err)
	}
	var disabled *types.DisabledException
	if errors.As(err, &disabled) {
		return fmt.Errorf("%w: %v", ErrKeyRevoked, err)
	}
	return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
}
