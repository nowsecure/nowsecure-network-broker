package config

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/rs/zerolog"
)

type Config struct {
	Log       LogConfig    `koanf:"log"`
	Wireguard TunnelConfig `koanf:"wireguard"`
	HubURL    string       `koanf:"hubURL"`
	Proxy     ProxyConfig  `koanf:"proxy"`
	Server    ServerConfig `koanf:"server"`
}

// ServerConfig holds configuration on whether to start an
// http server. Holds configuration such as adding health probes.
// If all options are false no server is started
type ServerConfig struct {
	// Probes adds the health probes of /healthz and /readyz
	// to the server useful in containerized envs
	Probes bool `koanf:"probes"`
	Port   int  `koanf:"port"`
}

// TunnelConfig holds the local wireguard tunnel parameters for the broker.
type TunnelConfig struct {
	PrivateKey        string        `koanf:"privateKey" yaml:"privateKey"`
	MTU               int           `koanf:"mtu" yaml:"mtu"`
	HubPublicKey      string        `koanf:"hubPublicKey" yaml:"hubPublicKey"`
	HeartbeatInterval time.Duration `koanf:"heartbeatInterval" yaml:"heartbeatInterval"`
}

// ProxyConfig describes which domains/URLs the broker should route.
type ProxyConfig struct {
	// Domains to be routed too. Typically a top level
	// such as acme.local would resolve for app.acme.local
	Domains []string `koanf:"domains"`
}

type LogConfig struct {
	Level  zerolog.Level `koanf:"level"`
	Pretty bool          `koanf:"pretty"`
}

var (
	defaultConfig = Config{
		Log: LogConfig{
			Level:  zerolog.InfoLevel,
			Pretty: false,
		},
		Wireguard: TunnelConfig{
			MTU: 1420,
		},
		Server: ServerConfig{
			Port: 8888,
		},
	}
)

func LoadConfig(ctx context.Context, k *koanf.Koanf, cfgFiles []string, cfg *Config) error {
	if err := k.Load(structs.Provider(defaultConfig, "koanf"), nil); err != nil {
		return fmt.Errorf("failed to load defaults: %w", err)
	}

	for _, cfgFile := range cfgFiles {
		if err := k.Load(file.Provider(cfgFile), yaml.Parser()); err != nil {
			return fmt.Errorf("failed to load config file %s: %w", cfgFile, err)
		}
	}
	if err := k.Unmarshal("", cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return cfg.Validate()
}

func (c *Config) Validate() error {
	raw, err := base64.StdEncoding.DecodeString(c.Wireguard.PrivateKey)
	if err != nil {
		return fmt.Errorf("wireguard.privateKey must be valid base64: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("wireguard.privateKey must be a 32-byte X25519 key (got %d bytes)", len(raw))
	}
	if c.Wireguard.HubPublicKey == "" {
		return fmt.Errorf("wireguard.hubPublicKey is required")
	}
	if c.HubURL == "" {
		return fmt.Errorf("hubURL is required")
	}
	return nil
}
