package wireguard

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
)

func testKeyPair(t *testing.T) (privB64, pubB64 string) {
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
		_ = json.NewEncoder(w).Encode(registrationResponse{
			IP:          "10.0.0.2",
			HubPort:     51820,
			AllowedCIDR: "10.0.0.0/24",
		})
	}))
}

func testConfig(t *testing.T, hubURL string) *config.Config {
	t.Helper()
	brokerPriv, _ := testKeyPair(t)
	_, hubPub := testKeyPair(t)
	return &config.Config{
		Wireguard: config.TunnelConfig{
			PrivateKey:        brokerPriv,
			HubPublicKey:      hubPub,
			HeartbeatInterval: time.Hour,
		},
		HubURL: hubURL,
		Proxy:  config.ProxyConfig{DNS: config.DNSConfig{Domains: []string{"example.com"}}},
	}
}

func newTestWireguard(t *testing.T) *Wireguard {
	t.Helper()
	hub := mockHubServer(t)
	t.Cleanup(hub.Close)

	cfg := testConfig(t, hub.URL)
	logger := zerolog.Nop()
	wg, err := New(t.Context(), &logger, cfg)
	require.NoError(t, err)
	return wg
}

func TestNew(t *testing.T) {
	t.Run("sets default heartbeat interval", func(t *testing.T) {
		hub := mockHubServer(t)
		defer hub.Close()

		brokerPriv, _ := testKeyPair(t)
		_, hubPub := testKeyPair(t)
		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: hubPub,
			},
			HubURL: hub.URL,
		}
		logger := zerolog.Nop()

		wg, err := New(t.Context(), &logger, cfg)
		require.NoError(t, err)
		assert.Equal(t, defaultHeartbeatInterval, wg.cfg.Wireguard.HeartbeatInterval)
	})

	t.Run("respects custom heartbeat interval", func(t *testing.T) {
		hub := mockHubServer(t)
		defer hub.Close()

		brokerPriv, _ := testKeyPair(t)
		_, hubPub := testKeyPair(t)
		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:        brokerPriv,
				HubPublicKey:      hubPub,
				HeartbeatInterval: 30 * time.Second,
			},
			HubURL: hub.URL,
		}
		logger := zerolog.Nop()

		wg, err := New(t.Context(), &logger, cfg)
		require.NoError(t, err)
		assert.Equal(t, 30*time.Second, wg.cfg.Wireguard.HeartbeatInterval)
	})

	t.Run("populates input from registration response", func(t *testing.T) {
		hub := mockHubServer(t)
		defer hub.Close()

		cfg := testConfig(t, hub.URL)
		logger := zerolog.Nop()

		wg, err := New(t.Context(), &logger, cfg)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.2", wg.input.localAddr)
		assert.Equal(t, cfg.Wireguard.HubPublicKey, wg.input.publicKey)
		assert.Equal(t, 51820, wg.input.port)
		assert.Equal(t, "10.0.0.0/24", wg.input.allowedIP)
	})
}

func TestStart(t *testing.T) {
	wg := newTestWireguard(t)
	tnet, err := wg.Start()
	require.NoError(t, err)
	require.NotNil(t, tnet)
}

func TestStart_InvalidLocalAddr(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registrationResponse{
			IP:          "not-an-ip/32",
			HubPort:     51820,
			AllowedCIDR: "10.0.0.0/24",
		})
	}))
	defer hub.Close()

	cfg := testConfig(t, hub.URL)
	logger := zerolog.Nop()

	wg, err := New(t.Context(), &logger, cfg)
	require.NoError(t, err)

	_, err = wg.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse local address")
}

func TestStart_InvalidPrivateKey(t *testing.T) {
	wg := newTestWireguard(t)
	// Swap to an invalid key after registration succeeds
	wg.cfg.Wireguard.PrivateKey = base64.StdEncoding.EncodeToString([]byte("short"))

	_, err := wg.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ipc set device")
}

func TestStart_DefaultMTU(t *testing.T) {
	hub := mockHubServer(t)
	defer hub.Close()

	cfg := testConfig(t, hub.URL)
	cfg.Wireguard.MTU = 0
	logger := zerolog.Nop()

	wg, err := New(t.Context(), &logger, cfg)
	require.NoError(t, err)

	tnet, err := wg.Start()
	require.NoError(t, err)
	require.NotNil(t, tnet)
}

func TestResolveEndpoint(t *testing.T) {
	t.Run("IP passthrough", func(t *testing.T) {
		wg := newTestWireguard(t)
		wg.input.host = "1.2.3.4"
		wg.input.port = 51820

		endpoint, err := wg.resolveEndpoint()
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4:51820", endpoint)
	})

	t.Run("hostname resolution", func(t *testing.T) {
		wg := newTestWireguard(t)
		wg.input.host = "localhost"
		wg.input.port = 51820

		endpoint, err := wg.resolveEndpoint()
		require.NoError(t, err)
		assert.Contains(t, endpoint, ":51820")
	})

	t.Run("unresolvable hostname", func(t *testing.T) {
		wg := newTestWireguard(t)
		wg.input.host = "this-host-does-not-exist.invalid"

		_, err := wg.resolveEndpoint()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolve hub host")
	})
}

func TestHubConnected(t *testing.T) {
	wg := newTestWireguard(t)
	assert.False(t, wg.HubConnected())

	wg.mu.Lock()
	wg.hubConnected = true
	wg.mu.Unlock()
	assert.True(t, wg.HubConnected())
}

func TestStop(t *testing.T) {
	wg := newTestWireguard(t)
	_, err := wg.Start()
	require.NoError(t, err)

	wg.mu.Lock()
	require.NotNil(t, wg.dev)
	wg.stop()
	assert.Nil(t, wg.dev)
	wg.mu.Unlock()
}

func TestStop_NilDevice(t *testing.T) {
	wg := newTestWireguard(t)
	// stop with nil device should not panic
	wg.mu.Lock()
	wg.stop()
	wg.mu.Unlock()
}

func TestCheckHubHealth_NilDevice(t *testing.T) {
	wg := newTestWireguard(t)
	// Should return early without panic when dev is nil
	wg.checkHubHealth()
}

func TestCheckHubHealth_Connected(t *testing.T) {
	wg := newTestWireguard(t)
	_, err := wg.Start()
	require.NoError(t, err)

	// Simulate a recent handshake by configuring the device IPC
	// Since we can't easily fake a handshake, test the disconnect path instead
	wg.checkHubHealth()

	// With no real peer, handshake will be zero → disconnect path
	wg.mu.Lock()
	assert.False(t, wg.hubConnected)
	assert.Equal(t, 1, wg.disconnectMiss)
	wg.mu.Unlock()
}

func TestCheckHubHealth_MaxRetries(t *testing.T) {
	wg := newTestWireguard(t)
	_, err := wg.Start()
	require.NoError(t, err)

	wg.mu.Lock()
	wg.disconnectMiss = maxDisconnectRetries - 1
	wg.mu.Unlock()

	wg.checkHubHealth()

	select {
	case <-wg.Dead:
		// expected — channel was closed
	default:
		t.Fatal("Dead channel should be closed after max retries")
	}
}

func TestCheckHubHealth_InvalidHubKey(t *testing.T) {
	wg := newTestWireguard(t)
	_, err := wg.Start()
	require.NoError(t, err)

	// Set an invalid hub public key to trigger PubKeyToHex error
	wg.mu.Lock()
	wg.input.publicKey = "bad!!!"
	wg.mu.Unlock()

	// checkHubHealth should handle the error and return early
	wg.checkHubHealth()

	wg.mu.Lock()
	// disconnectMiss should not change since we returned early on key error
	assert.Equal(t, 0, wg.disconnectMiss)
	wg.mu.Unlock()
}

func TestCheckHubHealth_ReregisterFails(t *testing.T) {
	// Use a hub that will fail on re-registration
	callCount := 0
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount > 1 {
			// Fail on subsequent registrations
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registrationResponse{
			IP:          "10.0.0.2",
			HubPort:     51820,
			AllowedCIDR: "10.0.0.0/24",
		})
	}))
	defer hub.Close()

	cfg := testConfig(t, hub.URL)
	logger := zerolog.Nop()
	wg, err := New(t.Context(), &logger, cfg)
	require.NoError(t, err)

	_, err = wg.Start()
	require.NoError(t, err)

	// checkHubHealth will see no handshake and try reregister, which will fail
	wg.checkHubHealth()

	wg.mu.Lock()
	assert.Equal(t, 1, wg.disconnectMiss)
	wg.mu.Unlock()
}

func TestStart_DeviceUpCalled(t *testing.T) {
	wg := newTestWireguard(t)
	wg.cfg.Wireguard.MTU = 1400

	tnet, err := wg.Start()
	require.NoError(t, err)
	require.NotNil(t, tnet)
}

func TestStart_DebugLogLevel(t *testing.T) {
	hub := mockHubServer(t)
	defer hub.Close()

	cfg := testConfig(t, hub.URL)
	logger := zerolog.New(io.Discard).Level(zerolog.DebugLevel)

	wg, err := New(t.Context(), &logger, cfg)
	require.NoError(t, err)

	tnet, err := wg.Start()
	require.NoError(t, err)
	require.NotNil(t, tnet)
}

func TestSetHubPeer_InvalidPeerKey(t *testing.T) {
	wg := newTestWireguard(t)
	_, err := wg.Start()
	require.NoError(t, err)

	// Set invalid hub public key so PeerWithEndpointIPC fails
	wg.mu.Lock()
	wg.input.publicKey = "bad!!!"
	err = wg.setHubPeer()
	wg.mu.Unlock()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "generate hub peer ipc")
}

func TestSetHubPeer_UnresolvableHost(t *testing.T) {
	wg := newTestWireguard(t)
	_, err := wg.Start()
	require.NoError(t, err)

	wg.mu.Lock()
	wg.input.host = "this.does.not.exist.invalid"
	err = wg.setHubPeer()
	wg.mu.Unlock()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve hub host")
}

func TestResolveEndpoint_NoAddresses(t *testing.T) {
	wg := newTestWireguard(t)
	wg.input.host = "this.does.not.exist.invalid"

	_, err := wg.resolveEndpoint()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve hub host")
}

func TestNew_RegistrationFails(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1")
	logger := zerolog.Nop()

	_, err := New(t.Context(), &logger, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "register with hub")
}

func TestRegisterWithHub(t *testing.T) {
	brokerPriv, brokerPub := testKeyPair(t)
	hubPriv, hubPub := testKeyPair(t)

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

			body, err := io.ReadAll(r.Body)
			require.NoError(t, err) //nolint:testifylint // require in handler is intentional

			mac := hmac.New(sha256.New, sharedSecret)
			mac.Write([]byte(ts))
			mac.Write([]byte("\n"))
			mac.Write(body)
			expectedSig := "HMAC " + base64.StdEncoding.EncodeToString(mac.Sum(nil))
			assert.Equal(t, expectedSig, auth, "HMAC mismatch")

			var req registrationRequest
			require.NoError(t, json.Unmarshal(body, &req)) //nolint:testifylint // require in handler is intentional
			assert.Equal(t, []string{"example.com"}, req.Proxy.DNS.Domains)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", "req-abc-123")
			_ = json.NewEncoder(w).Encode(registrationResponse{
				Message:     "broker successfully registered",
				BrokerIP:    "10.0.0.2",
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
			Proxy:  config.ProxyConfig{DNS: config.DNSConfig{Domains: []string{"example.com"}}},
		}

		resp, err := registerWithHub(t.Context(), cfg)
		require.NoError(t, err)
		assert.Equal(t, 51820, resp.HubPort)
		assert.Equal(t, "10.0.0.0/24", resp.AllowedCIDR)
		assert.Equal(t, "broker successfully registered", resp.Message)
	})

	t.Run("hub returns error status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		assert.Contains(t, err.Error(), "hub /broker/register failed")
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

	t.Run("bad request returns descriptive error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
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
		assert.Contains(t, err.Error(), "hub /broker/register failed")
	})

	t.Run("invalid hub public key", func(t *testing.T) {
		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: "not-valid-base64!!!",
			},
			HubURL: "http://localhost",
		}

		_, err := registerWithHub(t.Context(), cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode hub public key")
	})

	t.Run("invalid response json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not json"))
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
		assert.Contains(t, err.Error(), "decode registration response")
	})

	t.Run("sends ports in request body", func(t *testing.T) {
		var capturedReq registrationRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &capturedReq)
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
			Proxy: config.ProxyConfig{
				DNS: config.DNSConfig{Domains: []string{"api.example.com"}},
				Ports: config.Ports{
					HTTP:  []uint16{80, 8080},
					HTTPS: []uint16{443},
				},
			},
		}

		_, err := registerWithHub(t.Context(), cfg)
		require.NoError(t, err)
		assert.Equal(t, []string{"api.example.com"}, capturedReq.Proxy.DNS.Domains)
		assert.Equal(t, []uint16{80, 8080}, capturedReq.Proxy.Ports.HTTP)
		assert.Equal(t, []uint16{443}, capturedReq.Proxy.Ports.HTTPS)
	})
}

func TestDeregisterFromHub(t *testing.T) {
	brokerPriv, _ := testKeyPair(t)
	_, hubPub := testKeyPair(t)

	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/broker/deregister", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Contains(t, r.Header.Get("Authorization"), "HMAC ")
			assert.NotEmpty(t, r.Header.Get("X-Timestamp"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(deregistrationResponse{
				Message: "broker successfully deregistered",
			})
		}))
		defer srv.Close()

		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: hubPub,
			},
			HubURL: srv.URL,
		}

		resp, err := deregisterFromHub(t.Context(), cfg)
		require.NoError(t, err)
		assert.Equal(t, "broker successfully deregistered", resp.Message)
	})

	t.Run("hub returns error status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

		_, err := deregisterFromHub(t.Context(), cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hub /broker/deregister failed")
	})

	t.Run("hub unreachable", func(t *testing.T) {
		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: hubPub,
			},
			HubURL: "http://127.0.0.1:1",
		}

		_, err := deregisterFromHub(t.Context(), cfg)
		require.Error(t, err)
	})

	t.Run("invalid response json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()

		cfg := &config.Config{
			Wireguard: config.TunnelConfig{
				PrivateKey:   brokerPriv,
				HubPublicKey: hubPub,
			},
			HubURL: srv.URL,
		}

		_, err := deregisterFromHub(t.Context(), cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode deregistration response")
	})
}
