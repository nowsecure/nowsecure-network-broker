package wireguard

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey is a valid 32-byte X25519 key encoded as base64.
var testKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func TestDeviceIPC(t *testing.T) {
	ipc, err := DeviceIPC(testKey, 51820)
	require.NoError(t, err)

	want := "private_key=0000000000000000000000000000000000000000000000000000000000000000\nlisten_port=51820\n"
	assert.Equal(t, want, ipc)
}

func TestDeviceIPC_NoPort(t *testing.T) {
	ipc, err := DeviceIPC(testKey, 0)
	require.NoError(t, err)

	want := "private_key=0000000000000000000000000000000000000000000000000000000000000000\n"
	assert.Equal(t, want, ipc)
}

func TestPeerIPC(t *testing.T) {
	peer := PeerConfig{PublicKey: testKey, AllowedIP: "10.0.0.2/32"}
	ipc, err := PeerIPC(peer)
	require.NoError(t, err)

	want := "public_key=0000000000000000000000000000000000000000000000000000000000000000\nallowed_ip=10.0.0.2/32\n"
	assert.Equal(t, want, ipc)
}

func TestPeerWithKeepaliveIPC(t *testing.T) {
	peer := PeerConfig{PublicKey: testKey, AllowedIP: "10.0.0.2/32"}
	ipc, err := PeerWithKeepaliveIPC(peer, 25)
	require.NoError(t, err)

	want := "public_key=0000000000000000000000000000000000000000000000000000000000000000\n" +
		"allowed_ip=10.0.0.2/32\n" +
		"persistent_keepalive_interval=25\n"
	assert.Equal(t, want, ipc)
}

func TestPeerWithEndpointIPC(t *testing.T) {
	peer := PeerConfig{PublicKey: testKey, AllowedIP: "10.0.0.0/24"}
	ipc, err := PeerWithEndpointIPC(peer, "1.2.3.4:51820", 25)
	require.NoError(t, err)

	want := "public_key=0000000000000000000000000000000000000000000000000000000000000000\n" +
		"allowed_ip=10.0.0.0/24\n" +
		"endpoint=1.2.3.4:51820\n" +
		"persistent_keepalive_interval=25\n"
	assert.Equal(t, want, ipc)
}

func TestRemovePeerIPC(t *testing.T) {
	ipc, err := RemovePeerIPC(testKey)
	require.NoError(t, err)

	want := "public_key=0000000000000000000000000000000000000000000000000000000000000000\nremove=true\n"
	assert.Equal(t, want, ipc)
}

func TestParsePeerHandshake(t *testing.T) {
	hexKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	ipcOutput := "private_key=0000\nlisten_port=51820\npublic_key=" + hexKey + "\n" +
		"allowed_ip=10.0.0.2/32\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=0\n"

	ts := ParsePeerHandshake(ipcOutput, hexKey)
	assert.Equal(t, time.Unix(1700000000, 0), ts)
}

func TestParsePeerHandshake_NoPeer(t *testing.T) {
	ts := ParsePeerHandshake("private_key=0000\n", "deadbeef")
	assert.True(t, ts.IsZero())
}

func TestParseListenPort(t *testing.T) {
	ipc := "private_key=abc\nlisten_port=12345\npublic_key=def\n"
	port := ParseListenPort(ipc)
	assert.Equal(t, 12345, port)
}

func TestPubKeyToHex_Invalid(t *testing.T) {
	_, err := PubKeyToHex("not-valid-base64!!!")
	require.Error(t, err)
}
