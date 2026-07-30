# Clash HTTP Pool

This single Docker service reads a Clash YAML subscription and exposes each
proxy as a separate authenticated HTTP proxy port. Every generated listener
sets Mihomo's `proxy` field directly, so traffic on a port always uses its
assigned proxy and does not follow the subscription's rules.

The supplied subscription must be a Clash YAML document with a top-level
`proxies` array. URI-only subscriptions and `proxy-providers`-only documents
are intentionally rejected because they do not provide a stable complete node
list for port generation.

## Start

1. Create these three files. Each must contain one value and no quotes:

   ```text
   secrets/subscription_url.txt
   secrets/http_username.txt
   secrets/http_password.txt
   ```

2. Start the service:

   ```sh
   docker compose up -d --build
   ```

3. Inspect the generated map:

   ```sh
   cat data/ports.csv
   ```

Use the HTTP username and password with the port in `data/ports.csv`. For
example, a record for port `18000` is used as:

```text
http://USERNAME:PASSWORD@HOST:18000
```

`data/ports.json` and `data/ports.csv` never contain the subscription URL,
node credentials, or the HTTP proxy password. `data/mihomo` is Mihomo's
runtime cache for GEO data and selected state; it also does not contain the
subscription URL or node credentials.

## Defaults

The Compose file publishes `18000-18127`, allowing up to 128 nodes. The
container renews the subscription every hour. Existing node names retain their
assigned port whenever possible after an update.

Change the following values under `environment` in `compose.yaml` before the
first start when needed:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT_START` | `18000` | First generated HTTP proxy port. |
| `MAX_PROXIES` | `128` | Maximum number of matched nodes. |
| `UPDATE_INTERVAL_SECONDS` | `3600` | Subscription refresh interval. |
| `NODE_FILTER` | empty | Optional regular expression that selects nodes by name. |
| `LISTEN_ADDRESS` | `0.0.0.0` | Address used inside the container. |

When changing `PORT_START` or `MAX_PROXIES`, also change the published port
range in `compose.yaml` to match.

## Security

The service requires HTTP Basic authentication and strips the subscription's
legacy ports, TUN configuration, listeners, tunnels, DNS listener, dashboard,
and external control API. Do not remove authentication. HTTP Basic Auth is not
encrypted, so do not expose the published ports directly to the public
Internet. Limit access to a trusted LAN, VPN, or an encrypted reverse tunnel.

## Operations

View lifecycle logs:

```sh
docker compose logs -f proxy-pool
```

After updating a secret file, restart the container:

```sh
docker compose restart proxy-pool
```

When a subscription update changes the generated configuration, the container
validates it and restarts Mihomo. A fetch or validation failure leaves the last
working configuration running.
