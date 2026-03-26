package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/pkg/logger"
)

// ListenTCPFunc creates a TCP listener for a given address.
type ListenTCPFunc func(addr *net.TCPAddr) (net.Listener, error)

type Proxy struct {
	log   *zerolog.Logger
	ports *config.Ports
}

func New(log *zerolog.Logger, ports *config.Ports) *Proxy {
	l := log.With().
		Str("component", "proxy").Logger()

	return &Proxy{
		log:   &l,
		ports: ports,
	}
}

func (p *Proxy) Start(ctx context.Context, listen ListenTCPFunc) error {
	done := make(chan error, len(p.ports.HTTP)+len(p.ports.HTTPS))
	for _, port := range p.ports.HTTP {
		go func() { done <- p.startHTTPProxy(ctx, listen, int(port)) }()
	}
	for _, port := range p.ports.HTTPS {
		go func() { done <- p.startTLSPassthrough(ctx, listen, int(port)) }()
	}

	return <-done
}

// startHTTPProxy starts a plain http proxy for the desired port.
// The proxy will attempt to resolve and dial the specified host
// before transport
func (p *Proxy) startHTTPProxy(ctx context.Context, listen ListenTCPFunc, port int) error {
	l, err := listen(&net.TCPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				reqCtx := context.WithValue(ctx, logger.SpanIDKey, uuid.New().String())
				h, _, err := net.SplitHostPort(req.Host)
				if err != nil {
					h = req.Host
				}
				target, err := resolveHost(reqCtx, h, port)
				if err != nil {
					p.log.Error().Ctx(reqCtx).Err(err).Str("host", h).Msg("failed to resolve host")
					return
				}
				p.log.Info().Ctx(reqCtx).Msgf("HTTP: %s http://%s%s (%s → %s)", req.Method, h, req.URL.Path, h, target)
				req.URL.Scheme = "http"
				req.URL.Host = target
			},
		},
	}
	return server.Serve(l)
}

// startTLSPassthrough listens on the specified port, and peeks at the
// ClientHello to extract SNI Hostname. It uses this hostname to resolve and
// dial DNS. The TLS handshake is end to end with the final initiator of the
// connection and the final resource. This function DOES NOT terminate TLS.
func (p *Proxy) startTLSPassthrough(ctx context.Context, listen ListenTCPFunc, port int) error {
	l, err := listen(&net.TCPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go p.handleTLSConn(ctx, conn, port)
	}
}

// peekConn wraps a net.Conn, buffering all reads via TeeReader so the
// ClientHello bytes can be replayed to the backend. Writes are discarded
// to prevent tls.Server from sending alerts back to the real client.
type peekConn struct {
	net.Conn
	r io.Reader
}

func (c *peekConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *peekConn) Write(b []byte) (int, error) { return len(b), nil }

// extractSNI uses crypto/tls to parse the ClientHello from the connection
// and returns the SNI hostname
func extractSNI(client net.Conn) (sni string, peeked []byte) {
	var buf bytes.Buffer
	pc := &peekConn{
		Conn: client,
		r:    io.TeeReader(client, &buf),
	}

	tlsConn := tls.Server(pc, &tls.Config{ //nolint:gosec // TLS never completes; used only to parse ClientHello for SNI
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, fmt.Errorf("sni extracted")
		},
	})
	_ = tlsConn.Handshake() // fails intentionally after capturing SNI

	return sni, buf.Bytes()
}

func (p *Proxy) handleTLSConn(ctx context.Context, client net.Conn, port int) {
	defer client.Close()
	ctx = context.WithValue(ctx, logger.SpanIDKey, uuid.New().String())

	log := p.log.With().
		Str("handler", "TLS").
		Int("port", port).
		Logger()

	log.Info().Msg("attempting to proxy connection")
	sni, peeked := extractSNI(client)
	if sni == "" {
		log.Warn().Ctx(ctx).Msg("no SNI, dropping connection")
		return
	}

	backend, err := resolveHost(ctx, sni, port)
	if err != nil {
		log.Error().Ctx(ctx).Err(err).Str("target", sni).Msg("failed to resolve host")
		return
	}

	upstream, err := net.Dial("tcp", backend)
	if err != nil {
		log.Error().Ctx(ctx).Err(err).Str("target", sni).Str("backend", backend).Msg("dial failed")
		return
	}
	defer upstream.Close()

	log.Info().Ctx(ctx).
		Str("remote", client.RemoteAddr().String()).
		Str("backend", backend).
		Str("sni", sni).
		Msg("proxying TLS connection")

	// Replay the buffered ClientHello to the backend
	if _, err := upstream.Write(peeked); err != nil {
		log.Error().Ctx(ctx).Err(err).Str("backend", backend).Msg("replay ClientHello failed")
		return
	}

	// Bidirectional relay
	type closeWriter interface {
		CloseWrite() error
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		if cw, ok := upstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if cw, ok := client.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()
}

func resolveHost(ctx context.Context, h string, p int) (string, error) {
	addrs, err := net.LookupHost(h)
	if err != nil {
		return "", fmt.Errorf("failed to lookup host: %s err: %w", h, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for: %s", h)
	}
	for _, addr := range addrs {
		u := net.JoinHostPort(addr, strconv.Itoa(p))
		conn, err := net.DialTimeout("tcp", u, 2*time.Second)
		if err != nil {
			zerolog.Ctx(ctx).Warn().Ctx(ctx).Err(err).Msgf("cannot dial %s", u)
			continue
		}
		_ = conn.Close()
		return u, nil
	}
	return "", fmt.Errorf("no connectable address found for: %s", h)
}
