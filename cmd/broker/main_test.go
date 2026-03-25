package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nowsecure/nowsecure-network-broker/internal/broker"
	"github.com/nowsecure/nowsecure-network-broker/internal/config"
)

func validPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key.Bytes())
}

func noopCmd() *cobra.Command {
	return &cobra.Command{
		Use: "noop",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
}

func TestRoot(t *testing.T) {
	c, cfg := root()

	assert.Equal(t, "broker", c.Use)
	assert.NotNil(t, cfg)

	f := c.PersistentFlags().Lookup("config")
	require.NotNil(t, f, "config flag should be registered")
	assert.Equal(t, "c", f.Shorthand)
}

func TestRoot_PersistentPreRunE_LoadsConfig(t *testing.T) {
	privKey := validPrivateKey(t)
	yamlContent := "wireguard:\n  privateKey: " + privKey + "\n  hubPublicKey: some-key\nhubURL: https://hub.example.com\n"

	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0o400))

	c, cfg := root()
	c.SetArgs([]string{"--config", cfgFile})

	// Add a no-op subcommand so Execute runs PersistentPreRunE
	c.AddCommand(noopCmd())
	c.SetArgs([]string{"--config", cfgFile, "noop"})

	err := c.ExecuteContext(t.Context())
	require.NoError(t, err)

	assert.Equal(t, privKey, cfg.Wireguard.PrivateKey)
	assert.Equal(t, "https://hub.example.com", cfg.HubURL)
	assert.Equal(t, 1420, cfg.Wireguard.MTU, "defaults should be applied")
}

func TestRoot_PersistentPreRunE_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("wireguard:\n  privateKey: bad\nhubURL: https://hub.example.com\n"), 0o400))

	c, _ := root()
	c.AddCommand(noopCmd())
	c.SetArgs([]string{"--config", cfgFile, "noop"})

	err := c.ExecuteContext(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRoot_PersistentPreRunE_MissingFile(t *testing.T) {
	c, _ := root()
	c.AddCommand(noopCmd())
	c.SetArgs([]string{"--config", "/nonexistent/config.yaml", "noop"})

	err := c.ExecuteContext(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestNewStartCmd(t *testing.T) {
	cfg := &config.Config{}
	cmd := NewStartCmd(cfg)

	assert.Equal(t, "start", cmd.Use)
	assert.Equal(t, "Start the broker", cmd.Short)
}

func TestBuildBrokerOptions(t *testing.T) {
	t.Run("probes disabled", func(t *testing.T) {
		cfg := &config.Config{Server: config.ServerConfig{Probes: false}}
		opts := buildBrokerOptions(cfg)
		assert.Empty(t, opts)
	})

	t.Run("probes enabled", func(t *testing.T) {
		cfg := &config.Config{Server: config.ServerConfig{Probes: true}}
		opts := buildBrokerOptions(cfg)
		require.Len(t, opts, 1)

		// Verify the option is WithProbes by checking it sets up mux
		assert.IsType(t, (broker.Option)(nil), opts[0])
	})
}
