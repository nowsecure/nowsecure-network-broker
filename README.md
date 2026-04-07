# nowsecure-network-broker

The NowSecure Network Broker runs on a customer's network and
establishes a WireGuard tunnel back to a NowSecure hub. It proxies
HTTP/HTTPS traffic for configured domains through the tunnel, allowing NowSecure platform assessments to reach internal
applications without exposing them to the public internet.

## Configuration

The broker uses YAML config files loaded via the `-c` flag. Multiple
files can be specified and are merged in order, with later files
overriding earlier ones. This allows separating secrets from general
configuration.

### Minimum configuration

#### config.yaml

```yaml
hubURL: "https://hub.example.com"

proxy:
  domains:
    - "internal.example.com"

server:
  probes: true
```

### Secrets file

Keep sensitive values in a separate file with restricted permissions.
The second file overrides only the fields it specifies, so
`wireguard.privateKey` is merged into the base config.
Generate keys with standard WireGuard tooling:

```sh
wg genkey > private.key
wg pubkey < private.key > public.key
```

#### secret.yaml

```yaml
wireguard:
  privateKey: "oGo7PB3JCu/oBjrFGCVWS0hIijBaFUrh9LW1qdOqCW4="
  hubPublicKey: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
```

### Running

Download the latest binary from GitHub releases:

```sh
curl -L https://github.com/nowsecure/nowsecure-network-broker/releases/download/v0.0.1/nowsecure-network-broker-linux-arm64 \
  -o ./broker
chmod +x ./broker
./broker start -c config.yaml -c secret.yaml
```

### Running with Docker

```sh
docker run --rm \
  -v ./path/to/config.yaml:/etc/broker/config.yaml:ro \
  -v ./path/to/secret.yaml:/etc/broker/secret.yaml:ro \
  nowsecure/nowsecure-network-broker:stable \
  start -c /etc/broker/config.yaml -c /etc/broker/secret.yaml
```

See [config.example.yaml](/.ci/hack/config.yaml) for a full
annotated configuration reference.
