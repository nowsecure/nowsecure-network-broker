package wireguard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/pkg/logger"
	wgipc "github.com/nowsecure/nowsecure-network-broker/pkg/wireguard"
)

const (
	defaultMTU               = 1420
	defaultKeepalive         = 25
	defaultHeartbeatInterval = 20 * time.Second
	defaultHandshakeTimeout  = 3 * time.Minute
	maxDisconnectRetries     = 20
)

// registrationInfo holds connection details derived from hub registration.
type registrationInfo struct {
	publicKey string
	host      string
	port      int
	allowedIP string
	localAddr string
}

// Wireguard manages the broker's WireGuard tunnel to the hub.
type Wireguard struct {
	mu  sync.Mutex
	dev *device.Device

	hubConnected   bool
	disconnectMiss int

	// Dead is closed when the hub has been unreachable for
	// maxDisconnectRetries consecutive heartbeat checks.
	Dead chan struct{}

	cfg   *config.Config
	input *registrationInfo
	log   *zerolog.Logger
}

// New registers with the hub and returns a ready-to-start Wireguard instance.
func New(ctx context.Context, log *zerolog.Logger, cfg *config.Config) (*Wireguard, error) {
	if cfg.Wireguard.HeartbeatInterval == 0 {
		cfg.Wireguard.HeartbeatInterval = defaultHeartbeatInterval
	}
	l := log.With().
		Str("component", "tunnel").
		Logger()

	w := &Wireguard{
		log:  &l,
		cfg:  cfg,
		Dead: make(chan struct{}),
	}

	if err := w.register(ctx); err != nil {
		w.log.Warn().Msg("initial registration failed, hub may still be cleaning up the previous broker connection")
		return nil, err
	}
	return w, nil
}

// register calls the hub registration endpoint and populates w.input.
func (w *Wireguard) register(ctx context.Context) error {
	w.log.Info().Msgf("registering proxy config with hub: %s", w.cfg.HubURL)
	resp, err := registerWithHub(ctx, w.cfg)
	if err != nil {
		return fmt.Errorf("register with hub: %w", err)
	}
	w.log.Info().
		Int("wireguard_port", resp.HubPort).
		Msg("registered with hub")

	hubURL, _ := url.Parse(w.cfg.HubURL)

	w.input = &registrationInfo{
		publicKey: w.cfg.Wireguard.HubPublicKey,
		host:      hubURL.Hostname(),
		port:      resp.HubPort,
		allowedIP: resp.AllowedCIDR,
		localAddr: resp.IP,
	}
	return nil
}

// Start creates the WireGuard tunnel and connects to the hub.
func (w *Wireguard) Start() (*netstack.Net, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	localAddr, err := netip.ParseAddr(w.input.localAddr)
	if err != nil {
		return nil, fmt.Errorf("parse local address: %w", err)
	}

	mtu := w.cfg.Wireguard.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		nil,
		mtu,
	)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}

	devLogLevel := device.LogLevelSilent
	if w.log.GetLevel() <= zerolog.DebugLevel {
		devLogLevel = device.LogLevelVerbose
	}
	w.dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(devLogLevel, "wireguard: "))

	deviceIPC, err := wgipc.DeviceIPC(w.cfg.Wireguard.PrivateKey, 0)
	if err != nil {
		return nil, fmt.Errorf("generate device ipc: %w", err)
	}
	if err := w.dev.IpcSet(deviceIPC); err != nil {
		return nil, fmt.Errorf("ipc set device: %w", err)
	}

	if err := w.setHubPeer(); err != nil {
		return nil, err
	}

	if err := w.dev.Up(); err != nil {
		return nil, fmt.Errorf("device up: %w", err)
	}

	go w.runHeartbeat()

	w.log.Info().
		Str("local_addr", w.input.localAddr).
		Str("hub_host", w.input.host).
		Int("hub_port", w.input.port).
		Msg("wireguard tunnel started")

	return tnet, nil
}

// HubConnected returns true if the hub handshake is fresh.
func (w *Wireguard) HubConnected() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hubConnected
}

func (w *Wireguard) stop() {
	if w.dev != nil {
		w.dev.Close()
		w.dev = nil
	}
}

// resolveEndpoint resolves input.host to an IP.
func (w *Wireguard) resolveEndpoint() (string, error) {
	host := w.input.host
	ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		return "", fmt.Errorf("resolve hub host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve hub host %q: no addresses found", host)
	}
	return fmt.Sprintf("%s:%d", ips[0], w.input.port), nil
}

// setHubPeer configures the hub peer. Caller must hold w.mu.
func (w *Wireguard) setHubPeer() error {
	endpoint, err := w.resolveEndpoint()
	if err != nil {
		return err
	}

	hubPeer := wgipc.PeerConfig{
		Name:      "hub",
		PublicKey: w.input.publicKey,
		AllowedIP: w.input.allowedIP,
	}
	peerIPC, err := wgipc.PeerWithEndpointIPC(hubPeer, endpoint, defaultKeepalive)
	if err != nil {
		return fmt.Errorf("generate hub peer ipc: %w", err)
	}
	if err := w.dev.IpcSet(peerIPC); err != nil {
		return fmt.Errorf("ipc set hub peer: %w", err)
	}

	w.log.Info().Str("endpoint", endpoint).Msg("hub peer endpoint set")
	return nil
}

func (w *Wireguard) runHeartbeat() {
	ticker := time.NewTicker(w.cfg.Wireguard.HeartbeatInterval)
	defer ticker.Stop()

	for range ticker.C {
		w.checkHubHealth()
	}
}

func (w *Wireguard) checkHubHealth() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.dev == nil {
		return
	}

	ipcStr, err := w.dev.IpcGet()
	if err != nil {
		w.log.Error().Err(err).Msg("wireguard device failed, stopping tunnel")
		w.stop()
		return
	}

	hubKeyHex, err := wgipc.PubKeyToHex(w.input.publicKey)
	if err != nil {
		w.log.Error().Err(err).Msg("invalid hub public key")
		return
	}

	lastHandshake := wgipc.ParsePeerHandshake(ipcStr, hubKeyHex)
	if lastHandshake.IsZero() || time.Since(lastHandshake) > defaultHandshakeTimeout {
		w.hubConnected = false
		w.disconnectMiss++
		w.log.Warn().
			Int("miss", w.disconnectMiss).
			Int("max", maxDisconnectRetries).
			Msg("hub not connected, attempting re-registration")

		if w.disconnectMiss >= maxDisconnectRetries {
			w.log.Error().Msg("hub unreachable after max retries, giving up")
			close(w.Dead)
			return
		}

		if err := w.reregister(); err != nil {
			w.log.Warn().Err(err).Msg("reregister failed, will retry")
		}
		return
	}

	w.disconnectMiss = 0
	w.hubConnected = true
	w.log.Info().
		Time("last_handshake", lastHandshake).
		Msg("is connected to hub")
}

func (w *Wireguard) reregister() error {
	w.log.Info().Msg("attempting re-registration with hub")

	w.mu.Unlock()
	err := w.register(context.Background())
	w.mu.Lock()
	if err != nil {
		return fmt.Errorf("re-registration failed: %w", err)
	}

	if err := w.setHubPeer(); err != nil {
		return fmt.Errorf("failed to set hub peer: %w", err)
	}

	w.log.Info().
		Int("hub_port", w.input.port).
		Msg("re-registered with hub, waiting for handshake")
	return nil
}

type registrationRequest struct {
	Proxy config.ProxyConfig `json:"proxy"`
}

type registrationResponse struct {
	Message     string `json:"message"`
	IP          string `json:"ip"`
	BrokerIP    string `json:"brokerIP"`
	HubPort     int    `json:"hubPort"`
	AllowedCIDR string `json:"allowedCIDR"`
}

func registerWithHub(ctx context.Context, cfg *config.Config) (*registrationResponse, error) {
	privKey, err := base64.StdEncoding.DecodeString(cfg.Wireguard.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	hubPubKey, err := base64.StdEncoding.DecodeString(cfg.Wireguard.HubPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode hub public key: %w", err)
	}

	reqBody := registrationRequest{
		Proxy: cfg.Proxy,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal registration request: %w", err)
	}

	shared, err := curve25519.X25519(privKey, hubPubKey)
	if err != nil {
		return nil, fmt.Errorf("X25519: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("\n"))
	mac.Write(body)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	path, err := url.JoinPath(cfg.HubURL, "/broker/register")
	if err != nil {
		return nil, fmt.Errorf("failed to construct path: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("Authorization", "HMAC "+sig)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	id := resp.Header.Get("X-Request-ID")
	if id != "" {
		ctx = context.WithValue(ctx, logger.SpanIDKey, id)
	}

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Detail string `json:"detail"`
		}
		err = json.NewDecoder(resp.Body).Decode(&errBody)
		detail := errBody.Detail
		if err != nil {
			detail = err.Error()
		}
		if detail == "" {
			detail = "no detail provided in response"
		}
		err := fmt.Errorf("hub registration failed: %s", detail)
		zerolog.Ctx(ctx).Err(err).Int("status", resp.StatusCode).Ctx(ctx).Send()
		return nil, err
	}

	var regResp registrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		err := fmt.Errorf("decode registration response: %w", err)
		zerolog.Ctx(ctx).Err(err).Ctx(ctx).Send()
		return nil, err
	}

	return &regResp, nil
}
