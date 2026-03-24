package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PeerConfig defines a wireguard peer.
type PeerConfig struct {
	Name      string `json:"name" yaml:"name"`
	PublicKey string `json:"publicKey,omitempty" yaml:"publicKey"`
	AllowedIP string `json:"allowedIP" yaml:"allowedIP"`
}

// DeviceIPC generates the IPC config to initialize a WireGuard device
// with a private key and optional listen port.
func DeviceIPC(privateKeyB64 string, listenPort int) (string, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", hex.EncodeToString(privKeyBytes))
	if listenPort > 0 {
		fmt.Fprintf(&sb, "listen_port=%d\n", listenPort)
	}
	return sb.String(), nil
}

// PeerIPC generates the IPC config to add a peer with an allowed IP.
func PeerIPC(peer PeerConfig) (string, error) {
	pubKeyLine, err := PubKeyIPCLine(peer.PublicKey)
	if err != nil {
		return "", err
	}
	return pubKeyLine + fmt.Sprintf("allowed_ip=%s\n", peer.AllowedIP), nil
}

// PeerWithKeepaliveIPC generates IPC config for a peer with persistent keepalive.
func PeerWithKeepaliveIPC(peer PeerConfig, keepalive int) (string, error) {
	ipc, err := PeerIPC(peer)
	if err != nil {
		return "", err
	}
	return ipc + fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive), nil
}

// PeerWithEndpointIPC generates IPC config for a peer with an endpoint and keepalive.
func PeerWithEndpointIPC(peer PeerConfig, endpoint string, keepalive int) (string, error) {
	ipc, err := PeerIPC(peer)
	if err != nil {
		return "", err
	}
	if endpoint != "" {
		ipc += fmt.Sprintf("endpoint=%s\n", endpoint)
	}
	ipc += fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive)
	return ipc, nil
}

// RemovePeerIPC generates IPC config to remove a peer.
func RemovePeerIPC(publicKeyB64 string) (string, error) {
	pubKeyLine, err := PubKeyIPCLine(publicKeyB64)
	if err != nil {
		return "", err
	}
	return pubKeyLine + "remove=true\n", nil
}

// PubKeyIPCLine converts a base64 public key to the IPC format line.
func PubKeyIPCLine(publicKeyB64 string) (string, error) {
	hexKey, err := PubKeyToHex(publicKeyB64)
	if err != nil {
		return "", fmt.Errorf("invalid peer public key: %w", err)
	}
	return fmt.Sprintf("public_key=%s\n", hexKey), nil
}

// PubKeyToHex converts a base64-encoded key to hex encoding (used by WireGuard IPC).
func PubKeyToHex(b64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// ParsePeerHandshake finds the last_handshake_time_sec for a given peer
// in the WireGuard IPC output. The IPC format is line-based key=value with
// peers delimited by public_key= lines.
func ParsePeerHandshake(ipc, pubKeyHex string) time.Time {
	var inPeer bool
	for line := range strings.SplitSeq(ipc, "\n") {
		if key, ok := strings.CutPrefix(line, "public_key="); ok {
			inPeer = key == pubKeyHex
			continue
		}
		if inPeer {
			if val, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
				sec, _ := strconv.ParseInt(val, 10, 64)
				if sec == 0 {
					return time.Time{}
				}
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

// ParseListenPort extracts the listen_port from WireGuard IPC output.
func ParseListenPort(ipc string) int {
	for line := range strings.SplitSeq(ipc, "\n") {
		if val, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, _ := strconv.Atoi(val)
			return port
		}
	}
	return 0
}
