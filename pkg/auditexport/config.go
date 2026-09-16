package auditexport

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Backend names. The env var is SB_AUDIT_EXPORT_BACKEND.
const (
	BackendNoop    = "noop"
	BackendStdout  = "stdout"
	BackendFile    = "file"
	BackendWebhook = "webhook"
	BackendS3      = "s3"
	BackendBus     = "bus"
)

const (
	DefaultBatchMax      = 4096
	DefaultFlushInterval = time.Second
	DefaultMaxBackoff    = 5 * time.Minute
	DefaultTimeout       = 15 * time.Second
)

// Config is the backend-neutral configuration. internal/config parses the
// environment into it; this package only validates and builds.
type Config struct {
	Backend       string
	BatchMax      int
	FlushInterval time.Duration
	MaxBackoff    time.Duration
	// Timeout bounds one Export call for network backends.
	Timeout time.Duration
	// Enterprise tightens transport requirements (https + authenticated).
	Enterprise bool

	File    FileConfig
	Webhook WebhookConfig
	S3      S3Config
	Bus     BusConfig
}

// FileConfig drives the file and stdout backends. Path "-" means stdout.
type FileConfig struct {
	Path string
}

// WebhookConfig mirrors kube-apiserver's webhook backend: batched POST to one
// URL with transport-level authentication. Any of bearer, HMAC, or mTLS may
// be combined; enterprise requires at least one.
type WebhookConfig struct {
	URL         string
	BearerToken string
	// HMACKey signs the body: X-Aerol-Signature: sha256=<hex hmac>.
	HMACKey string
	// CAFile pins the receiver; CertFile/KeyFile present a client certificate.
	CAFile   string
	CertFile string
	KeyFile  string
}

// S3Config targets any S3-compatible object store. Credentials come from the
// default AWS chain (env, shared config, instance role), never from here.
type S3Config struct {
	Bucket    string
	Prefix    string
	Endpoint  string
	Region    string
	PathStyle bool
}

// BusConfig is consumed by a registered BusPublisher (Kafka, NATS, ...).
type BusConfig struct {
	Brokers string
	Topic   string
}

// IsOffNodeBackend reports whether name ships evidence to a system this node
// cannot silently rewrite. stdout, file and noop do not: losing the disk (or
// the operator with root on it) takes the reconstructable history with it,
// which is the single property the enterprise posture buys. Enterprise
// therefore accepts only these, or a programmatic exporter wired through
// controlplane.AuditExporter.
func IsOffNodeBackend(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case BackendWebhook, BackendS3, BackendBus:
		return true
	default:
		return false
	}
}

// WithDefaults fills zero values.
func (c Config) WithDefaults() Config {
	c.Backend = strings.ToLower(strings.TrimSpace(c.Backend))
	if c.Backend == "" {
		c.Backend = BackendNoop
	}
	if c.BatchMax <= 0 {
		c.BatchMax = DefaultBatchMax
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = DefaultFlushInterval
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = DefaultMaxBackoff
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	c.File.Path = strings.TrimSpace(c.File.Path)
	c.Webhook.URL = strings.TrimSpace(c.Webhook.URL)
	c.Webhook.BearerToken = strings.TrimSpace(c.Webhook.BearerToken)
	c.Webhook.HMACKey = strings.TrimSpace(c.Webhook.HMACKey)
	c.Webhook.CAFile = strings.TrimSpace(c.Webhook.CAFile)
	c.Webhook.CertFile = strings.TrimSpace(c.Webhook.CertFile)
	c.Webhook.KeyFile = strings.TrimSpace(c.Webhook.KeyFile)
	c.S3.Bucket = strings.TrimSpace(c.S3.Bucket)
	c.S3.Prefix = strings.Trim(strings.TrimSpace(c.S3.Prefix), "/")
	c.S3.Endpoint = strings.TrimSpace(c.S3.Endpoint)
	c.S3.Region = strings.TrimSpace(c.S3.Region)
	c.Bus.Brokers = strings.TrimSpace(c.Bus.Brokers)
	c.Bus.Topic = strings.TrimSpace(c.Bus.Topic)
	return c
}

// Validate checks the selected backend's requirements. It does not touch the
// network or the filesystem.
func (c Config) Validate() error {
	c = c.WithDefaults()
	if c.FlushInterval < 100*time.Millisecond {
		return errors.New("audit export flush interval must be >= 100ms")
	}
	if c.BatchMax > 65536 {
		return errors.New("audit export batch max must be <= 65536")
	}
	switch c.Backend {
	case BackendNoop, BackendStdout:
		if c.Enterprise {
			return fmt.Errorf("%w: %q keeps audit evidence on this node", ErrOnNodeBackend, c.Backend)
		}
		return nil
	case BackendFile:
		if c.File.Path == "" {
			return errors.New("SB_AUDIT_EXPORT_FILE_PATH is required for the file backend")
		}
		if c.Enterprise {
			return fmt.Errorf("%w: %q keeps audit evidence on this node", ErrOnNodeBackend, c.Backend)
		}
		return nil
	case BackendWebhook:
		if c.Webhook.URL == "" {
			return errors.New("SB_AUDIT_EXPORT_WEBHOOK_URL (or SB_SECRET_AUDIT_EXPORT_URL) is required for the webhook backend")
		}
		u, err := url.Parse(c.Webhook.URL)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("audit export webhook URL must be an absolute http(s) URL without userinfo")
		}
		if (c.Webhook.CertFile == "") != (c.Webhook.KeyFile == "") {
			return errors.New("audit export webhook mTLS requires both cert and key files")
		}
		if c.Enterprise {
			if u.Scheme != "https" {
				return errors.New("audit export webhook URL must use https when SB_ENTERPRISE_MODE=true")
			}
			if c.Webhook.BearerToken == "" && c.Webhook.HMACKey == "" && c.Webhook.CertFile == "" {
				return errors.New("audit export webhook requires SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN, SB_AUDIT_EXPORT_WEBHOOK_HMAC_KEY, or SB_AUDIT_EXPORT_WEBHOOK_CERT_FILE when SB_ENTERPRISE_MODE=true")
			}
		}
		return nil
	case BackendS3:
		if c.S3.Bucket == "" {
			return errors.New("SB_AUDIT_EXPORT_S3_BUCKET is required for the s3 backend")
		}
		if c.S3.Endpoint != "" {
			u, err := url.Parse(c.S3.Endpoint)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return errors.New("SB_AUDIT_EXPORT_S3_ENDPOINT must be an absolute http(s) URL")
			}
			if c.Enterprise && u.Scheme != "https" {
				return errors.New("SB_AUDIT_EXPORT_S3_ENDPOINT must use https when SB_ENTERPRISE_MODE=true")
			}
		}
		return nil
	case BackendBus:
		if c.Bus.Topic == "" {
			return errors.New("SB_AUDIT_EXPORT_BUS_TOPIC is required for the bus backend")
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnknownBackend, c.Backend)
	}
}
