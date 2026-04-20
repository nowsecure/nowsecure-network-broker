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

func testProxy(t *testing.T, ports config.Ports, domains, exclude []string) *Proxy {
	t.Helper()
	logger := zerolog.Nop()
	return New(&logger, &config.ProxyConfig{
		DNS:   config.DNSConfig{Domains: domains, Exclude: exclude},
		Ports: ports,
	})
}

func startProxy(t *testing.T, listenFn func(*net.TCPAddr) (*net.TCPListener, error), proxyFn func(ListenTCPFunc) error) string {
	t.Helper()
	listenerCh := make(chan net.Listener, 1)
	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		ln, err := listenFn(addr)
		if err == nil {
			listenerCh <- ln
		}
		return ln, err
	}

	go func() {
		if err := proxyFn(listen); err != nil {
			listenerCh <- nil // unblock select on error
		}
	}()

	select {
	case ln := <-listenerCh:
		require.NotNil(t, ln, "proxy listen failed")
		return ln.Addr().String()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxy listener")
		return ""
	}
}

func TestNew(t *testing.T) {
	p := testProxy(t, config.Ports{HTTP: []uint16{80}, HTTPS: []uint16{443}}, nil, nil)

	require.NotNil(t, p)
	assert.Equal(t, []uint16{80}, p.ports.HTTP)
	assert.Equal(t, []uint16{443}, p.ports.HTTPS)
}

func TestStart(t *testing.T) {
	p := testProxy(t, config.Ports{HTTP: []uint16{0}}, nil, nil)

	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		return net.ListenTCP("tcp", addr)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- p.Start(t.Context(), listen) }()

	require.Eventually(t, func() bool {
		select {
		case err := <-errCh:
			t.Fatalf("Start returned early: %v", err)
			return false
		default:
			return true
		}
	}, 2*time.Second, 50*time.Millisecond)
}

func TestStart_HTTPAndHTTPS(t *testing.T) {
	p := testProxy(t, config.Ports{HTTP: []uint16{0}, HTTPS: []uint16{0}}, nil, nil)

	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		return net.ListenTCP("tcp", addr)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- p.Start(t.Context(), listen) }()

	require.Eventually(t, func() bool {
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
	p := testProxy(t, config.Ports{HTTP: []uint16{80}}, nil, nil)

	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		return nil, fmt.Errorf("bind failed")
	}

	err := p.Start(t.Context(), listen)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen on port")
}

func TestStartHTTPProxy_Director(t *testing.T) {
	p := testProxy(t, config.Ports{HTTP: []uint16{0}}, nil, nil)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	_, backendPortStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	proxyAddr := startProxy(t,
		func(_ *net.TCPAddr) (*net.TCPListener, error) { return net.ListenTCP("tcp", &net.TCPAddr{}) },
		func(listen ListenTCPFunc) error { return p.startHTTPProxy(t.Context(), listen, backendPort) },
	)

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
			_ = tlsConn.Handshake()
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
	p := testProxy(t, config.Ports{HTTPS: []uint16{0}}, nil, nil)

	backendTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls backend ok"))
	}))
	defer backendTLS.Close()

	_, backendPortStr, _ := net.SplitHostPort(backendTLS.Listener.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	proxyAddr := startProxy(t,
		func(_ *net.TCPAddr) (*net.TCPListener, error) {
			return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		},
		func(listen ListenTCPFunc) error { return p.startTLSPassthrough(t.Context(), listen, backendPort) },
	)

	conn, err := tls.Dial("tcp4", proxyAddr, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, //nolint:gosec // test only, validating passthrough not cert
	})
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)

	body, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Contains(t, string(body), "tls backend ok")
}

func TestStartTLSPassthrough_ListenError(t *testing.T) {
	p := testProxy(t, config.Ports{HTTPS: []uint16{443}}, nil, nil)

	listen := func(addr *net.TCPAddr) (net.Listener, error) {
		return nil, fmt.Errorf("bind failed")
	}

	err := p.startTLSPassthrough(t.Context(), listen, 443)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen on port")
}

func TestHandleTLSConn_NoSNI(t *testing.T) {
	p := testProxy(t, config.Ports{HTTPS: []uint16{0}}, nil, nil)

	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("not a TLS handshake"))
	}()

	p.handleTLSConn(t.Context(), server, 443)
}

func TestHandleTLSConn_UnresolvableHost(t *testing.T) {
	p := testProxy(t, config.Ports{HTTPS: []uint16{0}}, nil, nil)

	proxyAddr := startProxy(t,
		func(_ *net.TCPAddr) (*net.TCPListener, error) {
			return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		},
		func(listen ListenTCPFunc) error { return p.startTLSPassthrough(t.Context(), listen, 443) },
	)

	conn, err := net.Dial("tcp4", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "this.host.does.not.exist.invalid",
		InsecureSkipVerify: true, //nolint:gosec // test only
	})
	err = tlsConn.Handshake()
	assert.Error(t, err)
}

func TestPeekConn_Write(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	pc := &peekConn{Conn: client, r: client}
	n, err := pc.Write([]byte("discarded"))
	require.NoError(t, err)
	assert.Equal(t, 9, n)
}

func TestHostAllowed(t *testing.T) {
	t.Run("empty domains allows everything", func(t *testing.T) {
		p := testProxy(t, config.Ports{}, nil, nil)
		assert.True(t, p.hostAllowed("anything.example.com"))
	})

	t.Run("exact match", func(t *testing.T) {
		p := testProxy(t, config.Ports{}, []string{"app.nowsecure.io"}, nil)
		assert.True(t, p.hostAllowed("app.nowsecure.io"))
		assert.False(t, p.hostAllowed("other.example.com"))
	})

	t.Run("subdomain match", func(t *testing.T) {
		p := testProxy(t, config.Ports{}, []string{"nowsecure.com"}, nil)
		assert.True(t, p.hostAllowed("nowsecure.com"))
		assert.True(t, p.hostAllowed("api.nowsecure.com"))
		assert.True(t, p.hostAllowed("deep.sub.nowsecure.com"))
		assert.False(t, p.hostAllowed("notnowsecure.com"))
	})

	t.Run("case insensitive", func(t *testing.T) {
		p := testProxy(t, config.Ports{}, []string{"NowSecure.COM"}, nil)
		assert.True(t, p.hostAllowed("nowsecure.com"))
		assert.True(t, p.hostAllowed("API.NOWSECURE.COM"))
	})

	t.Run("exclude takes precedence", func(t *testing.T) {
		p := testProxy(t, config.Ports{},
			[]string{"nowsecure.com"},
			[]string{"lode-runner.nowsecure.com"},
		)
		assert.True(t, p.hostAllowed("api.nowsecure.com"))
		assert.False(t, p.hostAllowed("lode-runner.nowsecure.com"))
	})

	t.Run("exclude is case insensitive", func(t *testing.T) {
		p := testProxy(t, config.Ports{},
			[]string{"nowsecure.com"},
			[]string{"Lode-Runner.NowSecure.com"},
		)
		assert.False(t, p.hostAllowed("lode-runner.nowsecure.com"))
	})

	t.Run("multiple domains", func(t *testing.T) {
		p := testProxy(t, config.Ports{},
			[]string{"app.nowsecure.io", "nowsecure.com"},
			nil,
		)
		assert.True(t, p.hostAllowed("app.nowsecure.io"))
		assert.True(t, p.hostAllowed("content-api.nowsecure.com"))
		assert.False(t, p.hostAllowed("evil.example.com"))
	})

	t.Run("not allowed when no match", func(t *testing.T) {
		p := testProxy(t, config.Ports{}, []string{"nowsecure.com"}, nil)
		assert.False(t, p.hostAllowed("evil.example.com"))
	})
}

func TestHTTPProxy_DeniedHost(t *testing.T) {
	p := testProxy(t, config.Ports{HTTP: []uint16{0}}, []string{"allowed.com"}, nil)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("should not reach"))
	}))
	defer backend.Close()

	_, backendPortStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	proxyAddr := startProxy(t,
		func(_ *net.TCPAddr) (*net.TCPListener, error) { return net.ListenTCP("tcp", &net.TCPAddr{}) },
		func(listen ListenTCPFunc) error { return p.startHTTPProxy(t.Context(), listen, backendPort) },
	)

	req, err := http.NewRequest(http.MethodGet, "http://"+proxyAddr+"/test", nil)
	require.NoError(t, err)
	req.Host = "evil.example.com"

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestTLSPassthrough_DeniedHost(t *testing.T) {
	p := testProxy(t, config.Ports{HTTPS: []uint16{0}}, []string{"allowed.com"}, nil)

	proxyAddr := startProxy(t,
		func(_ *net.TCPAddr) (*net.TCPListener, error) {
			return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		},
		func(listen ListenTCPFunc) error { return p.startTLSPassthrough(t.Context(), listen, 443) },
	)

	conn, err := net.Dial("tcp4", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "evil.example.com",
		InsecureSkipVerify: true, //nolint:gosec // test only
	})
	err = tlsConn.Handshake()
	assert.Error(t, err)
}
