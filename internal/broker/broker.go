package broker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/internal/wireguard"
	wgipc "github.com/nowsecure/nowsecure-network-broker/pkg/wireguard"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/curve25519"
)

type Broker struct {
	ctx context.Context
	log *zerolog.Logger
	wg  *wireguard.Wireguard
}

type registrationRequest struct {
	Peer  wgipc.PeerConfig `json:"peer"`
	Proxy proxyConfig      `json:"proxy"`
}

type proxyConfig struct {
	Domains     []string `json:"domains"`
	AllowedURLs []string `json:"allowedURLs"`
}

type registrationResponse struct {
	Message       string `json:"message"`
	IP            string `json:"ip"`
	BrokerIP      string `json:"brokerIP"`
	WireguardPort int    `json:"wireguardPort"`
	AllowedCIDR   string `json:"allowedCIDR"`
}

func New(ctx context.Context, cfg *config.Config) *Broker {
	log := zerolog.Ctx(ctx)

	log.Info().Msgf("registering proxy config with hub: %s", cfg.HubURL)
	resp, err := registerWithHub(ctx, cfg)
	if err != nil {
		log.Fatal().Ctx(ctx).Err(err).Msg("failed to register with hub")
	}

	log.Info().
		Int("wireguard_port", resp.WireguardPort).
		Msg("registered with hub")

	// url is validate from registerWithHub request
	hubURL, _ := url.Parse(cfg.HubURL)
	return &Broker{
		ctx: ctx,
		log: log,
		wg: wireguard.New(log, cfg.Wireguard, wireguard.HubInfo{
			PublicKey: cfg.Wireguard.HubPublicKey,
			Host:      hubURL.Hostname(),
			Port:      resp.WireguardPort,
			AllowedIP: resp.AllowedCIDR,
		}),
	}
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
		Peer: wgipc.PeerConfig{
			// this will almost always be the default
			AllowedIP: cfg.Wireguard.LocalAddr + "/32",
		},
		Proxy: proxyConfig{
			Domains:     cfg.Proxy.Domains,
			AllowedURLs: cfg.Proxy.AllowedURLs,
		},
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

	registerURL := cfg.HubURL + "/broker/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("Authorization", "HMAC "+sig)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", registerURL, err)
	}
	defer resp.Body.Close()

	id := resp.Header.Get("X-Request-ID")
	if id != "" {
		ctx = context.WithValue(ctx, "span-id", id)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("POST %s returned status %d", registerURL, resp.StatusCode)
		zerolog.Ctx(ctx).Err(err).Ctx(ctx).Send()
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

// Start wireguard tunnel and HTTP/HTTPS proxies
func (b *Broker) Start() error {
	tnet, err := b.wg.Start()
	if err != nil {
		return err
	}

	_ = tnet // TODO: use tnet for HTTP/TLS proxy listeners

	b.log.Info().Msg("broker started")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		b.log.Info().Msg("shutting down")
		return nil
	case <-b.wg.Dead:
		return fmt.Errorf("hub unreachable, exhausted reconnect attempts")
	}
}
