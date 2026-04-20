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
	Probes bool   `koanf:"probes"`
	Addr   string `koanf:"addr"`
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
	DNS   DNSConfig `koanf:"dns" json:"dns"`
	Ports Ports     `koanf:"ports" json:"ports"`
}

// DNSConfig controls which hostnames the proxy is allowed to route.
type DNSConfig struct {
	// Domains that are allowed. Both exact matches and subdomains are permitted.
	// e.g. "nowsecure.com" allows "nowsecure.com" and "api.nowsecure.com".
	Domains []string `koanf:"domains" json:"domains"`
	// Exclude denies specific hostnames that would otherwise be allowed by Domains.
	Exclude []string `koanf:"exclude" json:"exclude,omitempty"`
}

type Ports struct {
	// HTTP ports to proxy default is [80]
	HTTP []uint16 `koanf:"http" json:"http"`
	// HTTPS ports to proxy default is [443]
	HTTPS []uint16 `koanf:"https" json:"https"`
}

type LogConfig struct {
	Level  zerolog.Level `koanf:"level"`
	Pretty bool          `koanf:"pretty"`
}

var defaultConfig = Config{
	Log: LogConfig{
		Level:  zerolog.InfoLevel,
		Pretty: false,
	},
	Wireguard: TunnelConfig{
		MTU: 1420,
	},
	Server: ServerConfig{
		Addr: "127.0.0.1:8888",
	},
	Proxy: ProxyConfig{
		Ports: Ports{
			HTTP:  []uint16{80},
			HTTPS: []uint16{443},
		},
	},
}

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

func validateX25519Key(field, value string) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s must be valid base64: %w", field, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("%s must be a 32-byte X25519 key (got %d bytes)", field, len(raw))
	}
	return nil
}

func (c *Config) Validate() error {
	if err := validateX25519Key("wireguard.privateKey", c.Wireguard.PrivateKey); err != nil {
		return err
	}
	if err := validateX25519Key("wireguard.hubPublicKey", c.Wireguard.HubPublicKey); err != nil {
		return err
	}
	if c.HubURL == "" {
		return fmt.Errorf("hubURL is required")
	}
	return nil
}
