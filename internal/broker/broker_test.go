package broker

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/internal/proxy"
	"github.com/nowsecure/nowsecure-network-broker/internal/wireguard"
)

func testKeys(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

// mockHubServer returns an httptest.Server that responds to /broker/register.
func mockHubServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ip":          "10.0.0.2",
			"hubPort":     51820,
			"allowedCIDR": "10.0.0.0/24",
		})
	}))
}

func TestNew(t *testing.T) {
	brokerPriv, _ := testKeys(t)
	_, hubPub := testKeys(t)

	hub := mockHubServer(t)
	defer hub.Close()

	cfg := &config.Config{
		Wireguard: config.TunnelConfig{
			PrivateKey:   brokerPriv,
			HubPublicKey: hubPub,
		},
		HubURL: hub.URL,
		Proxy:  config.ProxyConfig{Domains: []string{"example.com"}},
	}

	logger := zerolog.Nop()
	ctx := logger.WithContext(t.Context())

	b, err := New(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.NotNil(t, b.wg)
}

func TestWithProbes_Healthz(t *testing.T) {
	t.Run("healthy when wg is set", func(t *testing.T) {
		b := &Broker{wg: &wireguard.Wireguard{}}
		WithProbes()(b)

		rec := httptest.NewRecorder()
		b.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "ok", rec.Body.String())
	})

	t.Run("unhealthy when wg is nil", func(t *testing.T) {
		b := &Broker{}
		WithProbes()(b)

		rec := httptest.NewRecorder()
		b.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "wireguard tunnel is not running")
	})
}

func TestWithProbes_Readyz(t *testing.T) {
	t.Run("not ready when wg is nil", func(t *testing.T) {
		b := &Broker{}
		WithProbes()(b)

		rec := httptest.NewRecorder()
		b.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "not ready")
	})

	t.Run("not ready when hub not connected", func(t *testing.T) {
		b := &Broker{wg: &wireguard.Wireguard{}}
		WithProbes()(b)

		rec := httptest.NewRecorder()
		b.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "not ready")
	})
}

func newTestBroker(t *testing.T, opts ...Option) *Broker {
	t.Helper()
	hub := mockHubServer(t)
	t.Cleanup(hub.Close)

	brokerPriv, _ := testKeys(t)
	_, hubPub := testKeys(t)

	logger := zerolog.Nop()
	log := &logger

	cfg := &config.Config{
		Wireguard: config.TunnelConfig{
			PrivateKey:        brokerPriv,
			HubPublicKey:      hubPub,
			HeartbeatInterval: time.Hour,
		},
		HubURL: hub.URL,
		Server: config.ServerConfig{Port: 0},
		Proxy: config.ProxyConfig{
			Ports: config.Ports{HTTP: []uint16{0}, HTTPS: []uint16{0}},
		},
	}

	wg, err := wireguard.New(t.Context(), log, cfg)
	require.NoError(t, err)

	b := &Broker{
		log:   log,
		proxy: proxy.New(log, &cfg.Proxy.Ports),
		cfg:   cfg,
		wg:    wg,
	}

	for _, opt := range opts {
		opt(b)
	}
	return b
}

func TestStart_SignalShutdown(t *testing.T) {
	b := newTestBroker(t)

	errCh := make(chan error, 1)
	go func() { errCh <- b.Start(t.Context()) }()

	// Give Start time to bring up the tunnel
	time.Sleep(100 * time.Millisecond)

	// Send SIGTERM to trigger clean shutdown
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after SIGTERM")
	}
}

func TestStart_DeadChannel(t *testing.T) {
	b := newTestBroker(t)

	errCh := make(chan error, 1)
	go func() { errCh <- b.Start(t.Context()) }()

	time.Sleep(100 * time.Millisecond)

	// Simulate hub unreachable by closing the Dead channel
	close(b.wg.Dead)

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hub unreachable")
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Dead closed")
	}
}

func TestClose_NilHTTP(t *testing.T) {
	b := &Broker{}
	// Should not panic when http is nil
	b.close()
}

func TestNew_RegistrationFailure(t *testing.T) {
	brokerPriv, _ := testKeys(t)
	_, hubPub := testKeys(t)

	cfg := &config.Config{
		Wireguard: config.TunnelConfig{
			PrivateKey:   brokerPriv,
			HubPublicKey: hubPub,
		},
		HubURL: "http://127.0.0.1:1", // unreachable
		Proxy:  config.ProxyConfig{Domains: []string{"example.com"}},
	}

	logger := zerolog.Nop()
	ctx := logger.WithContext(t.Context())

	_, err := New(ctx, cfg)
	require.Error(t, err)
}

func TestStart_WithProbes(t *testing.T) {
	b := newTestBroker(t, WithProbes())
	b.cfg.Server.Port = 18923

	errCh := make(chan error, 1)
	go func() { errCh <- b.Start(t.Context()) }()

	require.Eventually(t, func() bool {
		if b.http == nil {
			return false
		}
		resp, err := http.Get(fmt.Sprintf("http://localhost%s/healthz", b.http.Addr))
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "healthz probe never became reachable")

	_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after SIGTERM")
	}
}
