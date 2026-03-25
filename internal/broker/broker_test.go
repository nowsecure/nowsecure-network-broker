package broker

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

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
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
			require.NotEmpty(t, ts, "missing X-Timestamp")
			require.NotEmpty(t, auth, "missing Authorization")

			// Verify HMAC from the hub's perspective
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			mac := hmac.New(sha256.New, sharedSecret)
			mac.Write([]byte(ts))
			mac.Write([]byte("\n"))
			mac.Write(body)
			expectedSig := "HMAC " + base64.StdEncoding.EncodeToString(mac.Sum(nil))
			assert.Equal(t, expectedSig, auth, "HMAC mismatch")

			// Verify request body
			var req registrationRequest
			require.NoError(t, json.Unmarshal(body, &req))
			assert.Equal(t, []string{"example.com"}, req.Proxy.Domains)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", "req-abc-123")
			json.NewEncoder(w).Encode(registrationResponse{
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
			json.NewEncoder(w).Encode(registrationResponse{HubPort: 51820, AllowedCIDR: "10.0.0.0/24"})
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
		json.NewEncoder(w).Encode(registrationResponse{
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
		json.Unmarshal(body, &capturedReq)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registrationResponse{
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
	assert.Equal(t, []string{"/v1/.*"}, capturedReq.Proxy.AllowedURLs)
}
