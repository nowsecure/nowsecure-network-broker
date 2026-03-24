package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	wgipc "github.com/nowsecure/nowsecure-network-broker/pkg/wireguard"
	"github.com/rs/zerolog"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultMTU               = 1420
	defaultKeepalive         = 25
	defaultHeartbeatInterval = 10 * time.Second
	defaultHandshakeTimeout  = 1 * time.Minute
	maxDisconnectRetries     = 20
)

// HubInfo holds the connection details for the hub, populated from
// config (HubPublicKey) and the registration response (Host, Port, AllowedIP).
// Host can be a hostname or IP — it is resolved to an IP for the WireGuard endpoint.
type HubInfo struct {
	PublicKey string
	Host      string
	Port      int
	AllowedIP string
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

	cfg config.TunnelConfig
	hub HubInfo
	log *zerolog.Logger
}

func New(log *zerolog.Logger, cfg config.TunnelConfig, hub HubInfo) *Wireguard {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = defaultHeartbeatInterval
	}
	return &Wireguard{
		log:  log,
		cfg:  cfg,
		hub:  hub,
		Dead: make(chan struct{}),
	}
}

// Start creates the WireGuard tunnel and connects to the hub.
func (w *Wireguard) Start() (*netstack.Net, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	localAddr, err := netip.ParseAddr(w.cfg.LocalAddr)
	if err != nil {
		return nil, fmt.Errorf("parse local address: %w", err)
	}

	mtu := w.cfg.MTU
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

	w.dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	deviceIPC, err := wgipc.DeviceIPC(w.cfg.PrivateKey, 0)
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
		Str("local_addr", w.cfg.LocalAddr).
		Str("hub_host", w.hub.Host).
		Int("hub_port", w.hub.Port).
		Msg("wireguard tunnel started")

	return tnet, nil
}

func (w *Wireguard) stop() {
	if w.dev != nil {
		w.dev.Close()
		w.dev = nil
	}
}

// resolveEndpoint resolves hub.Host to an IP
func (w *Wireguard) resolveEndpoint() (string, error) {
	host := w.hub.Host
	ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		return "", fmt.Errorf("resolve hub host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve hub host %q: no addresses found", host)
	}
	return fmt.Sprintf("%s:%d", ips[0], w.hub.Port), nil
}

// setHubPeer configures hubPeer caller must lock
func (w *Wireguard) setHubPeer() error {
	endpoint, err := w.resolveEndpoint()
	if err != nil {
		return err
	}

	hubPeer := wgipc.PeerConfig{
		Name:      "hub",
		PublicKey: w.hub.PublicKey,
		AllowedIP: w.hub.AllowedIP,
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
	ticker := time.NewTicker(w.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for range ticker.C {
		w.checkHubHealth()
	}
}

// i think this can be put into the pkg/wireguard pkg
// i think we can make it generic
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

	hubKeyHex, err := wgipc.PubKeyToHex(w.hub.PublicKey)
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
			Msg("hub not connected, waiting for handshake")

		if w.disconnectMiss >= maxDisconnectRetries {
			w.log.Error().Msg("hub unreachable after max retries, giving up")
			close(w.Dead)
			return
		}

		// Re-resolve the hub endpoint in case the IP changed
		if err := w.setHubPeer(); err != nil {
			w.log.Error().Err(err).Msg("failed to re-resolve hub endpoint")
		}
		return
	}

	w.disconnectMiss = 0
	w.hubConnected = true
	w.log.Info().
		Time("last_handshake", lastHandshake).
		Msg("hub is connected")
}
