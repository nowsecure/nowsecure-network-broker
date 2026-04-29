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
	"strings"
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
	log     *zerolog.Logger
	ports   *config.Ports
	domains []string
	exclude []string
}

func New(log *zerolog.Logger, proxyCfg *config.ProxyConfig) *Proxy {
	l := log.With().
		Str("component", "proxy").Logger()

	return &Proxy{
		log:     &l,
		ports:   &proxyCfg.Ports,
		domains: proxyCfg.DNS.Domains,
		exclude: proxyCfg.DNS.Exclude,
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

// startHTTPProxy starts a plain HTTP reverse proxy on the given port.
func (p *Proxy) startHTTPProxy(ctx context.Context, listen ListenTCPFunc, port int) error {
	l, err := listen(&net.TCPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			reqCtx := context.WithValue(ctx, logger.SpanIDKey, uuid.New().String())
			h, _, err := net.SplitHostPort(req.Host)
			if err != nil {
				h = req.Host
			}
			target := net.JoinHostPort(h, strconv.Itoa(port))
			p.log.Info().Str("handler", "HTTP").
				Int("port", port).
				Ctx(reqCtx).
				Msgf("%s http://%s%s", req.Method, h, req.URL.Path)
			req.URL.Scheme = "http"
			req.URL.Host = target
		},
	}

	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			h, _, err := net.SplitHostPort(req.Host)
			if err != nil {
				h = req.Host
			}
			if !p.hostAllowed(h) {
				p.log.Warn().Str("host", h).Msg("host denied by allowlist")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			rp.ServeHTTP(w, req)
		}),
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
	tlsConn := tls.Server(
		&peekConn{
			Conn: client,
			r:    io.TeeReader(client, &buf),
		},
		//nolint:gosec // TLS never completes so TLS version doesn't matter;
		// used only to parse ClientHello for SNI
		&tls.Config{
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
		Ctx(ctx).
		Str("handler", "TLS").
		Int("port", port).
		Logger()

	log.Info().Msg("attempting to proxy connection")
	sni, peeked := extractSNI(client)
	if sni == "" {
		log.Warn().Msg("no SNI, dropping connection")
		return
	}

	if !p.hostAllowed(sni) {
		log.Warn().Str("sni", sni).Msg("host denied by allowlist")
		return
	}

	backend := net.JoinHostPort(sni, strconv.Itoa(port))
	upstream, err := net.Dial("tcp", backend)
	dialDuration := time.Since(time.Now()).Seconds()
	if err != nil {
		log.Error().
			Err(err).
			Str("target", sni).
			Str("backend", backend).
			Float64("dial_duration", dialDuration).
			Msg("dial failed")
		return
	}
	defer upstream.Close()

	log.Info().
		Str("remote", client.RemoteAddr().String()).
		Str("backend", backend).
		Str("sni", sni).
		Float64("dial_duration", dialDuration).
		Msg("finished dialing, proxying TLS connection")

	// Replay the buffered ClientHello to the backend
	if _, err := upstream.Write(peeked); err != nil {
		log.Error().Err(err).Str("backend", backend).Msg("replay ClientHello failed")
		return
	}

	relay(client, upstream)
}

// relay copies data bidirectionally between two connections,
// signaling half-close when each direction completes.
func relay(client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	go cp(upstream, client)
	go cp(client, upstream)

	wg.Wait()
}

// hostAllowed returns true if the hostname matches an allowed domain
// and is not in the exclude list.
func (p *Proxy) hostAllowed(hostname string) bool {
	if len(p.domains) == 0 {
		return true
	}
	for _, ex := range p.exclude {
		if strings.EqualFold(hostname, ex) {
			return false
		}
	}
	for _, d := range p.domains {
		if strings.EqualFold(hostname, d) {
			return true
		}
		// check if matches against subdomain
		if strings.HasSuffix(strings.ToLower(hostname), "."+strings.ToLower(d)) {
			return true
		}
	}
	return false
}
