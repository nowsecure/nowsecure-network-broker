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
			HubPublicKey: "aHViLXB1YmxpYy1rZXktdGhhdC1pcy0zMi1ieXRlcyE=",
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
		assert.Contains(t, err.Error(), "hubPublicKey must be a 32-byte")
	})

	t.Run("invalid base64 hub public key", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Wireguard.HubPublicKey = "not-valid!!!"
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hubPublicKey must be valid base64")
	})

	t.Run("wrong size hub public key", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Wireguard.HubPublicKey = base64.StdEncoding.EncodeToString([]byte("too-short"))
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hubPublicKey must be a 32-byte")
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
		yamlContent := "wireguard:\n  privateKey: " + privKey + "\n  hubPublicKey: aHViLXB1YmxpYy1rZXktdGhhdC1pcy0zMi1ieXRlcyE=\nhubURL: https://hub.example.com\n"

		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0o400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{cfgFile}, cfg)
		require.NoError(t, err)

		assert.Equal(t, 1420, cfg.Wireguard.MTU)
		assert.Equal(t, privKey, cfg.Wireguard.PrivateKey)
	})

	t.Run("file overrides defaults", func(t *testing.T) {
		privKey := validPrivateKey(t)
		yamlContent := "wireguard:\n  privateKey: " + privKey + "\n  hubPublicKey: aHViLXB1YmxpYy1rZXktdGhhdC1pcy0zMi1ieXRlcyE=\n  mtu: 1300\nhubURL: https://hub.example.com\n"

		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0o400))

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

	t.Run("multiple files merge in order", func(t *testing.T) {
		privKey := validPrivateKey(t)
		tmpDir := t.TempDir()

		base := filepath.Join(tmpDir, "base.yaml")
		require.NoError(t, os.WriteFile(base, []byte(
			"wireguard:\n  privateKey: "+privKey+"\n  hubPublicKey: aHViLXB1YmxpYy1rZXktdGhhdC1pcy0zMi1ieXRlcyE=\n  mtu: 1300\nhubURL: https://hub.example.com\n",
		), 0o400))

		override := filepath.Join(tmpDir, "override.yaml")
		require.NoError(t, os.WriteFile(override, []byte(
			"wireguard:\n  mtu: 1500\n",
		), 0o400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{base, override}, cfg)
		require.NoError(t, err)
		assert.Equal(t, 1500, cfg.Wireguard.MTU)
		assert.Equal(t, privKey, cfg.Wireguard.PrivateKey)
	})

	t.Run("invalid yaml syntax", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "bad.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte("{{invalid yaml"), 0o400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{cfgFile}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load config file")
	})

	t.Run("later file overrides only specified fields", func(t *testing.T) {
		privKey := validPrivateKey(t)
		tmpDir := t.TempDir()

		base := filepath.Join(tmpDir, "base.yaml")
		require.NoError(t, os.WriteFile(base, []byte(
			"wireguard:\n  privateKey: "+privKey+"\n  hubPublicKey: aHViLXB1YmxpYy1rZXktdGhhdC1pcy0zMi1ieXRlcyE=\nhubURL: https://hub.example.com\nserver:\n  addr: 0.0.0.0:9999\n",
		), 0o400))

		newHubKey := "b3ZlcnJpZGUta2V5LXRoYXQtaXMtMzItYnl0ZXMhISE="
		secret := filepath.Join(tmpDir, "secret.yaml")
		require.NoError(t, os.WriteFile(secret, []byte(
			"wireguard:\n  hubPublicKey: "+newHubKey+"\n",
		), 0o400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{base, secret}, cfg)
		require.NoError(t, err)
		assert.Equal(t, newHubKey, cfg.Wireguard.HubPublicKey)
		assert.Equal(t, "0.0.0.0:9999", cfg.Server.Addr)   // preserved from base
		assert.Equal(t, privKey, cfg.Wireguard.PrivateKey) // preserved from base
	})

	t.Run("empty config files uses defaults", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "empty.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte(""), 0o400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{cfgFile}, cfg)
		// Will fail validation (no private key) but should load defaults
		require.Error(t, err)
		assert.Contains(t, err.Error(), "privateKey")
	})

	t.Run("validation runs after load", func(t *testing.T) {
		yamlContent := "wireguard:\n  privateKey: bad\nhubURL: https://hub.example.com\n"

		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0o400))

		cfg := &Config{}
		err := LoadConfig(t.Context(), koanf.New("."), []string{cfgFile}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "privateKey must be valid base64")
	})
}
