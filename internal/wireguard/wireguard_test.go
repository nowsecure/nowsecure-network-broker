package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKeyPair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func TestNew(t *testing.T) {
	logger := zerolog.Nop()
	priv, pub := testKeyPair(t)

	t.Run("sets default heartbeat interval", func(t *testing.T) {
		cfg := config.TunnelConfig{PrivateKey: priv}
		input := RegistrationInfo{PublicKey: pub, Host: "127.0.0.1", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "10.0.0.2"}

		wg := New(&logger, cfg, input)

		require.NotNil(t, wg)
		assert.Equal(t, defaultHeartbeatInterval, wg.cfg.HeartbeatInterval)
	})

	t.Run("respects custom heartbeat interval", func(t *testing.T) {
		cfg := config.TunnelConfig{
			PrivateKey:        priv,
			HeartbeatInterval: 30 * time.Second,
		}
		input := RegistrationInfo{PublicKey: pub, Host: "127.0.0.1", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "10.0.0.2"}

		wg := New(&logger, cfg, input)

		assert.Equal(t, 30*time.Second, wg.cfg.HeartbeatInterval)
	})

	t.Run("stores config and registration input", func(t *testing.T) {
		cfg := config.TunnelConfig{PrivateKey: priv, MTU: 1300}
		input := RegistrationInfo{PublicKey: pub, Host: "5.6.7.8", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "10.0.0.2"}

		wg := New(&logger, cfg, input)

		assert.Equal(t, "10.0.0.2", wg.input.LocalAddr)
		assert.Equal(t, 1300, wg.cfg.MTU)
		assert.Equal(t, pub, wg.input.PublicKey)
		assert.Equal(t, "5.6.7.8", wg.input.Host)
		assert.Equal(t, 51820, wg.input.Port)
		assert.Equal(t, "10.0.0.0/24", wg.input.AllowedIP)
	})
}

func TestStart(t *testing.T) {
	logger := zerolog.Nop()
	brokerPriv, _ := testKeyPair(t)
	_, hubPub := testKeyPair(t)

	cfg := config.TunnelConfig{
		PrivateKey:        brokerPriv,
		HeartbeatInterval: time.Hour,
	}
	input := RegistrationInfo{
		PublicKey: hubPub,
		Host:      "127.0.0.1",
		Port:      51820,
		AllowedIP: "10.0.0.0/24",
		LocalAddr: "10.0.0.2",
	}

	wg := New(&logger, cfg, input)

	tnet, err := wg.Start()
	require.NoError(t, err)
	require.NotNil(t, tnet)
}

func TestStart_InvalidLocalAddr(t *testing.T) {
	logger := zerolog.Nop()
	priv, pub := testKeyPair(t)

	cfg := config.TunnelConfig{PrivateKey: priv}
	input := RegistrationInfo{PublicKey: pub, Host: "127.0.0.1", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "not-an-ip"}

	wg := New(&logger, cfg, input)
	_, err := wg.Start()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse local address")
}

func TestStart_InvalidPrivateKey(t *testing.T) {
	logger := zerolog.Nop()
	_, pub := testKeyPair(t)

	cfg := config.TunnelConfig{PrivateKey: "bad-key!!!"}
	input := RegistrationInfo{PublicKey: pub, Host: "127.0.0.1", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "10.0.0.2"}

	wg := New(&logger, cfg, input)
	_, err := wg.Start()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "generate device ipc")
}

func TestStart_DefaultMTU(t *testing.T) {
	logger := zerolog.Nop()
	brokerPriv, _ := testKeyPair(t)
	_, hubPub := testKeyPair(t)

	cfg := config.TunnelConfig{
		PrivateKey:        brokerPriv,
		MTU:               0,
		HeartbeatInterval: time.Hour,
	}
	input := RegistrationInfo{PublicKey: hubPub, Host: "127.0.0.1", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "10.0.0.2"}

	wg := New(&logger, cfg, input)
	tnet, err := wg.Start()
	require.NoError(t, err)
	require.NotNil(t, tnet)
}

func TestResolveEndpoint(t *testing.T) {
	logger := zerolog.Nop()
	priv, pub := testKeyPair(t)
	cfg := config.TunnelConfig{PrivateKey: priv}

	t.Run("IP passthrough", func(t *testing.T) {
		input := RegistrationInfo{PublicKey: pub, Host: "1.2.3.4", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "10.0.0.2"}
		wg := New(&logger, cfg, input)

		endpoint, err := wg.resolveEndpoint()
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4:51820", endpoint)
	})

	t.Run("hostname resolution", func(t *testing.T) {
		input := RegistrationInfo{PublicKey: pub, Host: "localhost", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "10.0.0.2"}
		wg := New(&logger, cfg, input)

		endpoint, err := wg.resolveEndpoint()
		require.NoError(t, err)
		assert.Contains(t, endpoint, ":51820")
	})

	t.Run("unresolvable hostname", func(t *testing.T) {
		input := RegistrationInfo{PublicKey: pub, Host: "this-host-does-not-exist.invalid", Port: 51820, AllowedIP: "10.0.0.0/24", LocalAddr: "10.0.0.2"}
		wg := New(&logger, cfg, input)

		_, err := wg.resolveEndpoint()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolve hub host")
	})
}
