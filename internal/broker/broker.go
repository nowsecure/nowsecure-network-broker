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

	"github.com/rs/zerolog"
	"golang.org/x/crypto/curve25519"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/internal/wireguard"
	"github.com/nowsecure/nowsecure-network-broker/logger"
)

type Broker struct {
	ctx context.Context
	log *zerolog.Logger
	wg  *wireguard.Wireguard
	cfg *config.Config

	http *http.Server
	mux  *http.ServeMux
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

type Option = func(b *Broker)

func New(ctx context.Context, cfg *config.Config, o ...Option) *Broker {
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

	b := &Broker{
		ctx: ctx,
		log: log,
		cfg: cfg,
		wg: wireguard.New(log, cfg.Wireguard, wireguard.RegistrationInfo{
			PublicKey: cfg.Wireguard.HubPublicKey,
			Host:      hubURL.Hostname(),
			Port:      resp.HubPort,
			AllowedIP: resp.AllowedCIDR,
			LocalAddr: localAddr,
		}),
	}

	for _, opt := range o {
		opt(b)
	}
	return b
}

func WithProbes() Option {
	return func(b *Broker) {
		if b.mux == nil {
			b.mux = http.NewServeMux()
		}
		b.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
			if b.wg == nil {
				http.Error(w, "wireguard tunnel is not running", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("ok"))
		})
		b.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
			if b.wg == nil || !b.wg.HubConnected() {
				http.Error(w, "not ready, hub not connected", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("ok"))
		})
	}
}

// Start wireguard tunnel and HTTP/HTTPS proxies
func (b *Broker) Start() error {
	tnet, err := b.wg.Start()
	if err != nil {
		return err
	}

	_ = tnet // TODO: use tnet for HTTP/TLS proxy listeners

	done := make(chan error, 1)
	if b.mux != nil {
		go func() { done <- b.serve() }()
	}

	b.log.Info().Msg("broker started")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		b.log.Info().Msg("shutting down")
		b.close()
		return nil
	case <-b.wg.Dead:
		b.close()
		return fmt.Errorf("hub unreachable, exhausted reconnect attempts")
	case err := <-done:
		b.close()
		return fmt.Errorf("http server: %w", err)
	}
}

func (b *Broker) serve() error {
	b.http = &http.Server{
		Addr:              fmt.Sprintf(":%d", b.cfg.Server.Port),
		Handler:           b.mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       10 * time.Second,
	}
	b.log.Info().Str("addr", b.http.Addr).Msg("starting http server")
	return b.http.ListenAndServe()
}

func (b *Broker) close() {
	if b.http == nil {
		return
	}
	_ = b.http.Close()
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
	defer func() { _ = resp.Body.Close() }()

	id := resp.Header.Get("X-Request-ID")
	if id != "" {
		ctx = context.WithValue(ctx, logger.SpanIDKey, id)
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
