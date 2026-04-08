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

func TestDeviceIPC_InvalidKey(t *testing.T) {
	_, err := DeviceIPC("not-valid-base64!!!", 51820)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}

func TestPeerIPC_InvalidKey(t *testing.T) {
	peer := PeerConfig{PublicKey: "bad!!!", AllowedIP: "10.0.0.0/24"}
	_, err := PeerIPC(peer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid peer public key")
}

func TestPeerWithKeepaliveIPC_InvalidKey(t *testing.T) {
	peer := PeerConfig{PublicKey: "bad!!!", AllowedIP: "10.0.0.0/24"}
	_, err := PeerWithKeepaliveIPC(peer, 25)
	require.Error(t, err)
}

func TestPeerWithEndpointIPC_InvalidKey(t *testing.T) {
	peer := PeerConfig{PublicKey: "bad!!!", AllowedIP: "10.0.0.0/24"}
	_, err := PeerWithEndpointIPC(peer, "1.2.3.4:51820", 25)
	require.Error(t, err)
}

func TestPeerWithEndpointIPC_EmptyEndpoint(t *testing.T) {
	peer := PeerConfig{PublicKey: testKey, AllowedIP: "10.0.0.0/24"}
	ipc, err := PeerWithEndpointIPC(peer, "", 25)
	require.NoError(t, err)

	assert.NotContains(t, ipc, "endpoint=")
	assert.Contains(t, ipc, "persistent_keepalive_interval=25")
}

func TestPubKeyIPCLine(t *testing.T) {
	line, err := PubKeyIPCLine(testKey)
	require.NoError(t, err)
	assert.Equal(t, "public_key=0000000000000000000000000000000000000000000000000000000000000000\n", line)
}

func TestPubKeyIPCLine_Invalid(t *testing.T) {
	_, err := PubKeyIPCLine("bad!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid peer public key")
}

func TestPubKeyToHex_Valid(t *testing.T) {
	hexStr, err := PubKeyToHex(testKey)
	require.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", hexStr)
}

func TestPubKeyToHex_Invalid(t *testing.T) {
	_, err := PubKeyToHex("not-valid-base64!!!")
	require.Error(t, err)
}

func TestParsePeerHandshake_ZeroTimestamp(t *testing.T) {
	hexKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	ipc := "public_key=" + hexKey + "\nlast_handshake_time_sec=0\n"

	ts := ParsePeerHandshake(ipc, hexKey)
	assert.True(t, ts.IsZero())
}

func TestParsePeerHandshake_MultiplePeers(t *testing.T) {
	key1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	key2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	ipc := "public_key=" + key1 + "\nlast_handshake_time_sec=1000\n" +
		"public_key=" + key2 + "\nlast_handshake_time_sec=2000\n"

	ts1 := ParsePeerHandshake(ipc, key1)
	assert.Equal(t, time.Unix(1000, 0), ts1)

	ts2 := ParsePeerHandshake(ipc, key2)
	assert.Equal(t, time.Unix(2000, 0), ts2)
}

func TestParseListenPort_NotPresent(t *testing.T) {
	port := ParseListenPort("private_key=abc\npublic_key=def\n")
	assert.Equal(t, 0, port)
}

func TestRemovePeerIPC_InvalidKey(t *testing.T) {
	_, err := RemovePeerIPC("bad!!!")
	require.Error(t, err)
}
