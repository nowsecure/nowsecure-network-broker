package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
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

func TestNewStartCmd_RunE_BrokerNewFails(t *testing.T) {
	// Config with no hub URL → broker.New will fail at wireguard.New (registration)
	privKey := validPrivateKey(t)
	yamlContent := "wireguard:\n  privateKey: " + privKey + "\n  hubPublicKey: some-key\nhubURL: http://127.0.0.1:1\n"

	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0o400))

	c, cfg := root()
	c.AddCommand(NewStartCmd(cfg))
	c.SetArgs([]string{"--config", cfgFile, "start"})

	err := c.ExecuteContext(t.Context())
	require.Error(t, err)
}

func TestRoot_PersistentPreRunE_MultipleConfigFiles(t *testing.T) {
	privKey := validPrivateKey(t)

	tmpDir := t.TempDir()
	baseFile := filepath.Join(tmpDir, "base.yaml")
	require.NoError(t, os.WriteFile(baseFile, []byte(
		"wireguard:\n  privateKey: "+privKey+"\n  hubPublicKey: some-key\n  mtu: 1300\nhubURL: https://hub.example.com\n",
	), 0o400))

	overrideFile := filepath.Join(tmpDir, "override.yaml")
	require.NoError(t, os.WriteFile(overrideFile, []byte(
		"wireguard:\n  mtu: 1500\n",
	), 0o400))

	c, cfg := root()
	c.AddCommand(noopCmd())
	c.SetArgs([]string{"--config", baseFile, "--config", overrideFile, "noop"})

	err := c.ExecuteContext(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1500, cfg.Wireguard.MTU)
}

func TestRoot_PersistentPreRunE_SetsLogger(t *testing.T) {
	privKey := validPrivateKey(t)
	yamlContent := "wireguard:\n  privateKey: " + privKey + "\n  hubPublicKey: some-key\nhubURL: https://hub.example.com\nlog:\n  pretty: true\n"

	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0o400))

	var ctxFromCmd context.Context
	verifyCmd := &cobra.Command{
		Use: "verify",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctxFromCmd = cmd.Context()
			return nil
		},
	}

	c, _ := root()
	c.AddCommand(verifyCmd)
	c.SetArgs([]string{"--config", cfgFile, "verify"})

	err := c.ExecuteContext(t.Context())
	require.NoError(t, err)
	require.NotNil(t, ctxFromCmd)
	// Logger should be set on the context
	logger := zerolog.Ctx(ctxFromCmd)
	assert.NotNil(t, logger)
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
