package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key.Bytes())
}

func validConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Wireguard: TunnelConfig{
			PrivateKey:   validPrivateKey(t),
			HubPublicKey: "aHViLXB1YmxpYy1rZXktdGhhdC1pcy0zMi1ieXRlcw==",
		},
		HubURL: "https://hub.example.com",
	}
}

func TestValidate(t *testing.T) {
	t.Run("valid config passes", func(t *testing.T) {
		cfg := validConfig(t)
		require.NoError(t, cfg.Validate())
	})

	t.Run("missing private key", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Wireguard.PrivateKey = ""
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "32-byte X25519 key")
	})

	t.Run("invalid base64 private key", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Wireguard.PrivateKey = "not-valid!!!"
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "privateKey must be valid base64")
	})

	t.Run("wrong size private key", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Wireguard.PrivateKey = base64.StdEncoding.EncodeToString([]byte("too-short"))
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "32-byte X25519 key")
	})

	t.Run("missing hub public key", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Wireguard.HubPublicKey = ""
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hubPublicKey is required")
	})

	t.Run("missing hub URL", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.HubURL = ""
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hubURL is required")
	})
}

func TestLoadConfig(t *testing.T) {
	t.Run("defaults are applied", func(t *testing.T) {
		privKey := validPrivateKey(t)
		yamlContent := "wireguard:\n  privateKey: " + privKey + "\n  hubPublicKey: some-key\nhubURL: https://hub.example.com\n"

		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{cfgFile}, cfg)
		require.NoError(t, err)

		assert.Equal(t, 1420, cfg.Wireguard.MTU)
		assert.Equal(t, privKey, cfg.Wireguard.PrivateKey)
	})

	t.Run("file overrides defaults", func(t *testing.T) {
		privKey := validPrivateKey(t)
		yamlContent := "wireguard:\n  privateKey: " + privKey + "\n  hubPublicKey: some-key\n  mtu: 1300\nhubURL: https://hub.example.com\n"

		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{cfgFile}, cfg)
		require.NoError(t, err)

		assert.Equal(t, 1300, cfg.Wireguard.MTU)
	})

	t.Run("missing config file fails", func(t *testing.T) {
		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{"/nonexistent/config.yaml"}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load config file")
	})

	t.Run("validation runs after load", func(t *testing.T) {
		yamlContent := "wireguard:\n  privateKey: bad\nhubURL: https://hub.example.com\n"

		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{cfgFile}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "privateKey must be valid base64")
	})
}
