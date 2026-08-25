package lab

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains the runtime settings for the lab server.
type Config struct {
	Addr              string
	AppName           string
	MaxBodyBytes      int64
	MaxDelay          time.Duration
	TrustProxyHeaders bool
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// DefaultConfig returns conservative defaults suitable for a container behind
// a reverse proxy. Proxy headers are intentionally untrusted by default.
func DefaultConfig() Config {
	return Config{
		Addr:              ":8080",
		AppName:           "Yandex SWS Test Lab",
		MaxBodyBytes:      1 << 20, // 1 MiB
		MaxDelay:          2 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
}

// LoadConfig reads supported environment variables and validates them.
func LoadConfig() (Config, error) {
	cfg := DefaultConfig()

	if value := strings.TrimSpace(os.Getenv("ADDR")); value != "" {
		cfg.Addr = value
	} else if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return Config{}, fmt.Errorf("PORT must be an integer between 1 and 65535")
		}
		cfg.Addr = ":" + port
	}

	if value := strings.TrimSpace(os.Getenv("APP_NAME")); value != "" {
		cfg.AppName = value
	}

	if value := strings.TrimSpace(os.Getenv("MAX_BODY_BYTES")); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 1024 || n > 10<<20 {
			return Config{}, fmt.Errorf("MAX_BODY_BYTES must be between 1024 and 10485760")
		}
		cfg.MaxBodyBytes = n
	}

	if value := strings.TrimSpace(os.Getenv("MAX_DELAY_MS")); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 10_000 {
			return Config{}, fmt.Errorf("MAX_DELAY_MS must be between 0 and 10000")
		}
		cfg.MaxDelay = time.Duration(n) * time.Millisecond
	}

	if value := strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")); value != "" {
		trusted, err := strconv.ParseBool(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRUST_PROXY_HEADERS must be true or false: %w", err)
		}
		cfg.TrustProxyHeaders = trusted
	}

	return cfg, nil
}
