package integration_test

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/nowsecure/nowsecure-network-broker/internal/broker"
	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	pkglogger "github.com/nowsecure/nowsecure-network-broker/pkg/logger"
	wgipc "github.com/nowsecure/nowsecure-network-broker/pkg/wireguard"
)

type keyPair struct {
	privB64 string
	pubB64  string
}

func generateKey(t *testing.T) keyPair {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return keyPair{
		privB64: base64.StdEncoding.EncodeToString(key.Bytes()),
		pubB64:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
	}
}

func hexKey(t *testing.T, b64Key string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	require.NoError(t, err)
	return hex.EncodeToString(raw)
}

type registrationResponse struct {
	Message     string `json:"message"`
	IP          string `json:"ip"`
	BrokerIP    string `json:"brokerIP"`
	HubPort     int    `json:"hubPort"`
	AllowedCIDR string `json:"allowedCIDR"`
}

// mockHub creates a test HTTP server that handles broker registration with
// HMAC-SHA256 signature verification, returning the WireGuard connection details.
func mockHub(t *testing.T, hubKey, brokerKey keyPair, wgPort int) *httptest.Server {
	t.Helper()

	hubPrivBytes, err := base64.StdEncoding.DecodeString(hubKey.privB64)
	require.NoError(t, err)
	brokerPubBytes, err := base64.StdEncoding.DecodeString(brokerKey.pubB64)
	require.NoError(t, err)
	sharedSecret, err := curve25519.X25519(hubPrivBytes, brokerPubBytes)
	require.NoError(t, err)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/broker/register" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		ts := r.Header.Get("X-Timestamp")
		auth := r.Header.Get("Authorization")
		if ts == "" || auth == "" {
			http.Error(w, "missing auth headers", http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		mac := hmac.New(sha256.New, sharedSecret)
		mac.Write([]byte(ts))
		mac.Write([]byte("\n"))
		mac.Write(body)
		expectedSig := "HMAC " + base64.StdEncoding.EncodeToString(mac.Sum(nil))

		if auth != expectedSig {
			http.Error(w, "invalid signature", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registrationResponse{
			Message:     "broker successfully registered",
			IP:          "10.0.0.2",
			BrokerIP:    "10.0.0.2",
			HubPort:     wgPort,
			AllowedCIDR: "10.0.0.0/24",
		})
	}))
}

func handshakeComplete(t *testing.T, dev *device.Device, peerPubHex string) bool {
	t.Helper()
	ipc, err := dev.IpcGet()
	if err != nil {
		return false
	}
	return !wgipc.ParsePeerHandshake(ipc, peerPubHex).IsZero()
}

func TestBrokerHTTPSPassthrough(t *testing.T) {
	hubKey := generateKey(t)
	brokerKey := generateKey(t)

	hubTUN, hubNet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		nil,
		1420,
	)
	require.NoError(t, err)

	hubDev := device.NewDevice(hubTUN, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer hubDev.Close()

	deviceIPC, err := wgipc.DeviceIPC(hubKey.privB64, 0)
	require.NoError(t, err)
	require.NoError(t, hubDev.IpcSet(deviceIPC))

	peerIPC, err := wgipc.PeerWithKeepaliveIPC(wgipc.PeerConfig{
		Name:      "broker",
		PublicKey: brokerKey.pubB64,
		AllowedIP: "10.0.0.2/32",
	}, 1)
	require.NoError(t, err)
	require.NoError(t, hubDev.IpcSet(peerIPC))
	require.NoError(t, hubDev.Up())

	ipc, err := hubDev.IpcGet()
	require.NoError(t, err)
	hubWGPort := wgipc.ParseListenPort(ipc)
	require.NotZero(t, hubWGPort)

	hub := mockHub(t, hubKey, brokerKey, hubWGPort)
	defer hub.Close()

	ctx := pkglogger.NewLogger(true, zerolog.InfoLevel, "").WithContext(t.Context())

	cfg := &config.Config{
		Log: config.LogConfig{
			Pretty: true,
		},
		Wireguard: config.TunnelConfig{
			PrivateKey:        brokerKey.privB64,
			HubPublicKey:      hubKey.pubB64,
			HeartbeatInterval: 500 * time.Millisecond,
		},
		HubURL: hub.URL,
		Proxy: config.ProxyConfig{
			Domains: []string{"www.nowsecure.com"},
			Ports: config.Ports{
				HTTPS: []uint16{443},
			},
		},
	}

	b, err := broker.New(ctx, cfg)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() { errCh <- b.Start(ctx) }()

	// Wait for the WireGuard handshake.
	brokerPubHex := hexKey(t, brokerKey.pubB64)
	require.Eventually(t, func() bool {
		return handshakeComplete(t, hubDev, brokerPubHex)
	}, 10*time.Second, 200*time.Millisecond, "broker handshake with hub did not complete")

	tcpConn, err := hubNet.DialContextTCPAddrPort(
		t.Context(),
		netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 443),
	)
	require.NoError(t, err)
	defer tcpConn.Close()

	tlsClient := tls.Client(tcpConn, &tls.Config{
		ServerName: "www.nowsecure.com",
	})
	require.NoError(t, tlsClient.Handshake())

	_, err = tlsClient.Write([]byte("GET / HTTP/1.1\r\nHost: www.nowsecure.com\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)

	body, err := io.ReadAll(tlsClient)
	require.NoError(t, err)
	resp := string(body)
	assert.Contains(t, resp, "nowsecure")

	if m := regexp.MustCompile(`<title>(.*?)</title>`).FindStringSubmatch(resp); len(m) > 1 {
		t.Logf("\n\nTLS passthrough succeeded — page title: %s\n\n", m[1])
	}

	select {
	case err := <-errCh:
		t.Fatalf("broker.Start returned unexpectedly: %v", err)
	default:
	}
}
