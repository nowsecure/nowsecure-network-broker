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
	"strings"
	"syscall"
	"time"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/internal/wireguard"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/curve25519"
)

type Broker struct {
	ctx context.Context
	log *zerolog.Logger
	wg  *wireguard.Wireguard
}

type registrationRequest struct {
	Proxy proxyConfig `json:"proxy"`
}

type proxyConfig struct {
	Domains     []string `json:"domains"`
	AllowedURLs []string `json:"allowedURLs"`
}

type registrationResponse struct {
	Message     string `json:"message"`
	IP          string `json:"ip"`
	BrokerIP    string `json:"brokerIP"`
	HubPort     int    `json:"hubPort"`
	AllowedCIDR string `json:"allowedCIDR"`
}

func New(ctx context.Context, cfg *config.Config) *Broker {
	log := zerolog.Ctx(ctx)

	log.Info().Msgf("registering proxy config with hub: %s", cfg.HubURL)
	resp, err := registerWithHub(ctx, cfg)
	if err != nil {
		log.Fatal().Ctx(ctx).Err(err).Msg("failed to register with hub")
	}

	log.Info().
		Int("wireguard_port", resp.HubPort).
		Msg("registered with hub")

	// url is validated from registerWithHub request
	hubURL, _ := url.Parse(cfg.HubURL)
	// resp.IP is "10.0.0.2/32", remove the /32
	localAddr, _, _ := strings.Cut(resp.IP, "/")

	return &Broker{
		ctx: ctx,
		log: log,
		wg: wireguard.New(log, cfg.Wireguard, wireguard.RegistrationInfo{
			PublicKey: cfg.Wireguard.HubPublicKey,
			Host:      hubURL.Hostname(),
			Port:      resp.HubPort,
			AllowedIP: resp.AllowedCIDR,
			LocalAddr: localAddr,
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
		Proxy: proxyConfig{
			Domains: cfg.Proxy.Domains,
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
