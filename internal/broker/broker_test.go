package broker

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/internal/wireguard"
)

func testKeys(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func TestRegisterWithHub(t *testing.T) {
	brokerPriv, brokerPub := testKeys(t)
	hubPriv, hubPub := testKeys(t)

	hubPrivBytes, _ := base64.StdEncoding.DecodeString(hubPriv)
	brokerPubBytes, _ := base64.StdEncoding.DecodeString(brokerPub)
	sharedSecret, err := curve25519.X25519(hubPrivBytes, brokerPubBytes)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/broker/register", r.URL.Path)

			ts := r.Header.Get("X-Timestamp")
			auth := r.Header.Get("Authorization")
			require.NotEmpty(t, ts, "missing X-Timestamp")     //nolint:testifylint // require in handler is intentional
			require.NotEmpty(t, auth, "missing Authorization") //nolint:testifylint // require in handler is intentional

			// Verify HMAC from the hub's perspective
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err) //nolint:testifylint // require in handler is intentional

			mac := hmac.New(sha256.New, sharedSecret)
			mac.Write([]byte(ts))
			mac.Write([]byte("\n"))
			mac.Write(body)
			expectedSig := "HMAC " + base64.StdEncoding.EncodeToString(mac.Sum(nil))
			assert.Equal(t, expectedSig, auth, "HMAC mismatch")

			// Verify request body
			var req registrationRequest
			require.NoError(t, json.Unmarshal(body, &req)) //nolint:testifylint // require in handler is intentional
			assert.Equal(t, []string{"example.com"}, req.Proxy.Domains)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", "req-abc-123")
			_ = json.NewEncoder(w).Encode(registrationResponse{
				Message:     "broker successfully registered",
				BrokerIP:    "10.0.0.2/32",
				HubPort:     51820,
				AllowedCIDR: "10.0.0.0/24",
			})
		}))
		defer srv.Close()

		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: hubPub,
			},
			HubURL: srv.URL,
			Proxy:  config.ProxyConfig{Domains: []string{"example.com"}},
		}

		resp, err := registerWithHub(t.Context(), cfg)
		require.NoError(t, err)
		assert.Equal(t, 51820, resp.HubPort)
		assert.Equal(t, "10.0.0.0/24", resp.AllowedCIDR)
		assert.Equal(t, "broker successfully registered", resp.Message)
	})

	t.Run("hub returns error status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: hubPub,
			},
			HubURL: srv.URL,
		}

		_, err := registerWithHub(t.Context(), cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "returned status 500")
	})

	t.Run("hub unreachable", func(t *testing.T) {
		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: hubPub,
			},
			HubURL: "http://127.0.0.1:1",
		}

		_, err := registerWithHub(t.Context(), cfg)
		require.Error(t, err)
	})

	t.Run("invalid private key", func(t *testing.T) {
		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   "not-valid-base64!!!",
				HubPublicKey: hubPub,
			},
			HubURL: "http://localhost",
		}

		_, err := registerWithHub(t.Context(), cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode private key")
	})

	t.Run("timestamp is current", func(t *testing.T) {
		var capturedTimestamp int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ts, _ := strconv.ParseInt(r.Header.Get("X-Timestamp"), 10, 64)
			capturedTimestamp = ts
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(registrationResponse{HubPort: 51820, AllowedCIDR: "10.0.0.0/24"})
		}))
		defer srv.Close()

		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: hubPub,
			},
			HubURL: srv.URL,
		}

		_, err := registerWithHub(t.Context(), cfg)
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now(), time.Unix(capturedTimestamp, 0), 5*time.Second)
	})
}

func TestNew(t *testing.T) {
	brokerPriv, _ := testKeys(t)
	_, hubPub := testKeys(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registrationResponse{
			Message:     "broker successfully registered",
			BrokerIP:    "10.0.0.2/32",
			HubPort:     51820,
			AllowedCIDR: "10.0.0.0/24",
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		Wireguard: config.TunnelConfig{
			PrivateKey:   brokerPriv,
			HubPublicKey: hubPub,
		},
		HubURL: srv.URL,
		Proxy:  config.ProxyConfig{Domains: []string{"example.com"}},
	}

	logger := zerolog.Nop()
	ctx := logger.WithContext(t.Context())

	b := New(ctx, cfg)
	require.NotNil(t, b)
	assert.NotNil(t, b.wg)
}

func TestNew_RegistrationRequestBody(t *testing.T) {
	brokerPriv, _ := testKeys(t)
	_, hubPub := testKeys(t)

	var capturedReq registrationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedReq)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registrationResponse{
			HubPort:     51820,
			AllowedCIDR: "10.0.0.0/24",
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		Wireguard: config.TunnelConfig{
			PrivateKey:   brokerPriv,
			HubPublicKey: hubPub,
		},
		HubURL: srv.URL,
		Proxy: config.ProxyConfig{
			Domains: []string{"api.example.com"},
		},
	}

	logger := zerolog.Nop()
	ctx := logger.WithContext(t.Context())
	_ = New(ctx, cfg)

	assert.Equal(t, []string{"api.example.com"}, capturedReq.Proxy.Domains)
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
	brokerPriv, _ := testKeys(t)
	_, hubPub := testKeys(t)

	logger := zerolog.Nop()
	log := &logger

	b := &Broker{
		log: log,
		cfg: &config.Config{
			Server: config.ServerConfig{Port: 0},
		},
		wg: wireguard.New(log, config.TunnelConfig{
			PrivateKey:        brokerPriv,
			HeartbeatInterval: time.Hour,
		}, wireguard.RegistrationInfo{
			PublicKey: hubPub,
			Host:      "127.0.0.1",
			Port:      51820,
			AllowedIP: "10.0.0.0/24",
			LocalAddr: "10.0.0.2",
		}),
	}

	for _, opt := range opts {
		opt(b)
	}
	return b
}

func TestStart_SignalShutdown(t *testing.T) {
	b := newTestBroker(t)

	errCh := make(chan error, 1)
	go func() { errCh <- b.Start() }()

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
	go func() { errCh <- b.Start() }()

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

func TestStart_WithProbes(t *testing.T) {
	b := newTestBroker(t, WithProbes())
	b.cfg.Server.Port = 18923

	errCh := make(chan error, 1)
	go func() { errCh <- b.Start() }()

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
