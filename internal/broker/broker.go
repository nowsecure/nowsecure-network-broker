package broker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/internal/proxy"
	"github.com/nowsecure/nowsecure-network-broker/internal/wireguard"
)

type Broker struct {
	proxy *proxy.Proxy
	log   *zerolog.Logger
	wg    *wireguard.Wireguard
	cfg   *config.Config

	http *http.Server
	mux  *http.ServeMux
}

type Option = func(b *Broker)

func New(ctx context.Context, cfg *config.Config, o ...Option) (*Broker, error) {
	log := zerolog.Ctx(ctx)

	wg, err := wireguard.New(ctx, log, cfg)
	if err != nil {
		return nil, err
	}

	b := &Broker{
		proxy: proxy.New(log, &cfg.Proxy),
		log:   log,
		cfg:   cfg,
		wg:    wg,
	}

	for _, opt := range o {
		opt(b)
	}
	return b, nil
}

func WithProbes() Option {
	return func(b *Broker) {
		b.mux = http.NewServeMux()
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
func (b *Broker) Start(ctx context.Context) error {
	tnet, err := b.wg.Start()
	if err != nil {
		return err
	}

	done := make(chan error, 2)
	go func() {
		done <- b.proxy.Start(ctx, proxy.ListenTCPFunc(func(addr *net.TCPAddr) (net.Listener, error) {
			return tnet.ListenTCP(addr)
		}))
	}()

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
		return err
	}
}

func (b *Broker) serve() error {
	b.http = &http.Server{
		Addr:              b.cfg.Server.Addr,
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
	if b.wg != nil {
		if err := b.wg.Deregister(); err != nil {
			b.log.Error().Err(err).Msg("failed to deregister from hub")
		}
	}
	if b.http != nil {
		_ = b.http.Close()
	}
}
