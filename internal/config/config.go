package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultToolboxPort = 2280

type Config struct {
	PATToken            string
	APIHost             string
	APIPort             int
	Domain              string
	PublicHost          string
	CaddyAdminURL       string
	CaddyServerID       string
	DBPath              string
	DockerNetwork       string
	ToolboxBinaryPath   string
	ToolboxMountPath    string
	ToolboxPort         int
	IdleTimeoutMinutes  int
	ContainerPrivileged bool
	ResourceLimitsOff   bool
	AutoReconcile       bool
	EnableCaddy         bool
	EnableNetworkRules  bool
	LogLevel            string
	ShutdownTimeout     time.Duration
	HTTPClientTimeout   time.Duration
}

func Load() (Config, error) {
	exe, _ := os.Executable()
	defaultToolboxPath := filepath.Join(filepath.Dir(exe), "toolboxd")

	cfg := Config{
		PATToken:            firstNonEmptyEnv("SB_PAT_TOKEN", "SB_API_TOKEN"),
		APIHost:             getEnv("SB_API_HOST", "0.0.0.0"),
		APIPort:             getEnvInt("SB_API_PORT", 8080),
		Domain:              normalizeHost(os.Getenv("SB_DOMAIN")),
		PublicHost:          normalizeHost(getEnv("SB_PUBLIC_HOST", "127.0.0.1")),
		CaddyAdminURL:       getEnv("SB_CADDY_ADMIN_URL", "http://127.0.0.1:2019"),
		CaddyServerID:       getEnv("SB_CADDY_SERVER_ID", "srv0"),
		DBPath:              getEnv("SB_DB_PATH", "/var/lib/sandboxd/state.db"),
		DockerNetwork:       getEnv("SB_DOCKER_NETWORK", "bridge"),
		ToolboxBinaryPath:   getEnv("SB_TOOLBOX_BINARY_PATH", defaultToolboxPath),
		ToolboxMountPath:    getEnv("SB_TOOLBOX_MOUNT_PATH", "/usr/local/bin/toolboxd"),
		ToolboxPort:         getEnvInt("SB_TOOLBOX_PORT", defaultToolboxPort),
		IdleTimeoutMinutes:  getEnvInt("SB_IDLE_TIMEOUT_MIN", 0),
		ContainerPrivileged: getEnvBool("SB_CONTAINER_PRIVILEGED", false),
		ResourceLimitsOff:   getEnvBool("SB_RESOURCE_LIMITS_DISABLED", false),
		AutoReconcile:       getEnvBool("SB_AUTO_RECONCILE", true),
		EnableCaddy:         getEnvBool("SB_ENABLE_CADDY", true),
		EnableNetworkRules:  getEnvBool("SB_ENABLE_NETWORK_RULES", true),
		LogLevel:            strings.ToLower(getEnv("SB_LOG_LEVEL", "info")),
		ShutdownTimeout:     getEnvDuration("SB_SHUTDOWN_TIMEOUT", 10*time.Second),
		HTTPClientTimeout:   getEnvDuration("SB_HTTP_CLIENT_TIMEOUT", 10*time.Second),
	}

	if cfg.PATToken == "" {
		return Config{}, errors.New("SB_PAT_TOKEN is required")
	}

	if cfg.DBPath == "" {
		return Config{}, errors.New("SB_DB_PATH is required")
	}

	if cfg.ToolboxMountPath == "" || !strings.HasPrefix(cfg.ToolboxMountPath, "/") {
		return Config{}, fmt.Errorf("SB_TOOLBOX_MOUNT_PATH must be an absolute path")
	}

	if cfg.Domain == "" && cfg.PublicHost == "" {
		return Config{}, errors.New("SB_PUBLIC_HOST is required when SB_DOMAIN is empty")
	}

	return cfg, nil
}

func (c Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.APIHost, c.APIPort)
}

func (c Config) DomainMode() bool {
	return c.Domain != ""
}

func (c Config) IdleTimeout() time.Duration {
	if c.IdleTimeoutMinutes <= 0 {
		return 0
	}
	return time.Duration(c.IdleTimeoutMinutes) * time.Minute
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func normalizeHost(value string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://"))
}
