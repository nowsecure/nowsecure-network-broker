package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nowsecure/nowsecure-network-broker/internal/config"
)

func TestNew(t *testing.T) {
	logger := zerolog.Nop()
	ports := &config.Ports{HTTP: []uint16{80}, HTTPS: []uint16{443}}

	p := New(&logger, ports)

	require.NotNil(t, p)
	assert.Equal(t, ports, p.ports)
}

func TestResolveHost_Connectable(t *testing.T) {
	// Start a TCP listener to resolve and connect to
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	hostPort, err := resolveHost(t.Context(), "localhost", port)
	require.NoError(t, err)

	host, returnedPort, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	assert.Equal(t, portStr, returnedPort)
	ip := net.ParseIP(host)
	require.NotNil(t, ip, "expected valid IP, got %s", host)
}

func TestResolveHost_UnknownHost(t *testing.T) {
	_, err := resolveHost(t.Context(), "this.host.does.not.exist.invalid", 80)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to lookup host")
}

func TestStart(t *testing.T) {
	logger := zerolog.Nop()
	ports := &config.Ports{HTTP: []uint16{0}}
	p := New(&logger, ports)

	// Use a standard net listener as the factory
	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		return net.ListenTCP("tcp", addr)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- p.Start(t.Context(), listen) }()

	// Wait for the HTTP server to come up by polling
	require.Eventually(t, func() bool {
		if p.ports == nil {
			return false
		}
		// port 0 means we can't predict it, but the server should be running
		// Just verify Start hasn't errored yet
		select {
		case err := <-errCh:
			t.Fatalf("Start returned early: %v", err)
			return false
		default:
			return true
		}
	}, 2*time.Second, 50*time.Millisecond)
}

func TestStart_ListenError(t *testing.T) {
	logger := zerolog.Nop()
	ports := &config.Ports{HTTP: []uint16{80}}
	p := New(&logger, ports)

	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		return nil, fmt.Errorf("bind failed")
	}

	err := p.Start(t.Context(), listen)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen on port")
}

func TestStartHTTPProxy_Director(t *testing.T) {
	logger := zerolog.Nop()
	ports := &config.Ports{HTTP: []uint16{0}}
	p := New(&logger, ports)

	// Backend that the proxy will forward to
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	_, backendPortStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	// Start the proxy on a random port
	var proxyListener net.Listener
	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		ln, err := net.ListenTCP("tcp", addr)
		proxyListener = ln
		return ln, err
	}

	errCh := make(chan error, 1)
	go func() { errCh <- p.startHTTPProxy(t.Context(), listen, backendPort) }()

	require.Eventually(t, func() bool {
		return proxyListener != nil
	}, 2*time.Second, 10*time.Millisecond)

	proxyAddr := proxyListener.Addr().String()

	t.Run("sets scheme and host", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://"+proxyAddr+"/test", nil)
		require.NoError(t, err)
		req.Host = "127.0.0.1:" + backendPortStr

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "backend ok", string(body))
	})

	t.Run("host without port falls back", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://"+proxyAddr+"/test", nil)
		require.NoError(t, err)
		// Host without port triggers SplitHostPort error → fallback to req.Host
		req.Host = "127.0.0.1"

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "backend ok", string(body))
	})
}

func TestExtractSNI(t *testing.T) {
	t.Run("extracts SNI from ClientHello", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()

		go func() {
			defer client.Close()
			tlsConn := tls.Client(client, &tls.Config{
				ServerName:         "example.com",
				InsecureSkipVerify: true, //nolint:gosec // test only
			})
			_ = tlsConn.Handshake() // will fail, we only need the ClientHello sent
		}()

		sni, peeked := extractSNI(server)
		assert.Equal(t, "example.com", sni)
		assert.NotEmpty(t, peeked, "peeked bytes should contain the ClientHello")
	})

	t.Run("empty SNI when no ServerName", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()

		go func() {
			defer client.Close()
			tlsConn := tls.Client(client, &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test only
			})
			_ = tlsConn.Handshake()
		}()

		sni, _ := extractSNI(server)
		assert.Empty(t, sni)
	})
}

func TestStartTLSPassthrough(t *testing.T) {
	logger := zerolog.Nop()
	ports := &config.Ports{HTTPS: []uint16{0}}
	p := New(&logger, ports)

	// Backend: a real TLS server. Go's httptest cert covers "localhost".
	backendTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls backend ok"))
	}))
	defer backendTLS.Close()

	_, backendPortStr, _ := net.SplitHostPort(backendTLS.Listener.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	// Start the TLS passthrough proxy on an explicit IPv4 address
	// to avoid port collision with the backend on IPv6.
	// Start the TLS passthrough proxy on a fixed IPv4 address to
	// prevent resolveHost from connecting to the proxy itself via [::1].
	var proxyListener net.Listener
	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		proxyListener = ln
		return ln, err
	}

	errCh := make(chan error, 1)
	go func() { errCh <- p.startTLSPassthrough(t.Context(), listen, backendPort) }()

	require.Eventually(t, func() bool {
		return proxyListener != nil
	}, 2*time.Second, 10*time.Millisecond)

	proxyAddr := proxyListener.Addr().String()

	// SNI must be a hostname (not an IP) — TLS clients don't send SNI for IPs.
	// Use "localhost" which resolves to 127.0.0.1.
	conn, err := tls.Dial("tcp4", proxyAddr, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, //nolint:gosec // test only, validating passthrough not cert
	})
	require.NoError(t, err)
	defer conn.Close()

	// Make an HTTP/1.1 request over the passthrough TLS connection
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)

	body, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Contains(t, string(body), "tls backend ok")
}

func TestStartTLSPassthrough_ListenError(t *testing.T) {
	logger := zerolog.Nop()
	ports := &config.Ports{HTTPS: []uint16{443}}
	p := New(&logger, ports)

	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		return nil, fmt.Errorf("bind failed")
	}

	err := p.startTLSPassthrough(t.Context(), listen, 443)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen on port")
}

func TestResolveHost_NotConnectable(t *testing.T) {
	// Pick a port that nothing is listening on
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close() // close immediately so nothing is listening

	_, err = resolveHost(t.Context(), "localhost", port)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no connectable address found")
}
