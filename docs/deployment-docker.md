# Docker Deployment

`rustydnsd` ships a small multi-stage image (~30 MB compressed) plus an
example `docker-compose.yml`. This doc covers the moving parts an
operator actually has to make decisions about.

For the broader security model see [`docs/security.md`](security.md);
for the management endpoints see
[`docs/operator-endpoints.md`](operator-endpoints.md).

## TL;DR

```bash
git clone https://github.com/Iwan-Teague/rustydns.git
cd rustydns
cp rustydns.example.toml rustydns.toml
$EDITOR rustydns.toml
docker compose up -d
```

Then point a client at the host on port 53 (UDP/TCP), 853 (DoT), or
8053 (DoH).

## Image layout

The `Dockerfile` is multi-stage:

- **`builder`** — `rust:1.88-bookworm`. Copies workspace manifests
  first so Cargo's dep graph is cached independently of source churn,
  then builds `rustydnsd` with the workspace's release profile (`lto =
  "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`).
- **`runtime`** — `debian:bookworm-slim`. Pulls in `libcap2-bin` (for
  the `setcap` step at image build time) and `tini` (PID 1 init).
  **`ca-certificates` is intentionally not installed** — the resolver
  embeds the Mozilla CA bundle via the `webpki-roots` feature, so the
  runtime trust store is invariant from the host's.

The binary lives at `/usr/local/bin/rustydnsd`, owned `root:rustydns`
with mode `0750`. `setcap cap_net_bind_service=+ep` is applied at
build time so the non-root `rustydns` user can still bind `:53` and
`:853`.

## Capability model

The image runs as the non-root `rustydns` system user (uid/gid
assigned by Debian). The only capability it needs at runtime is
`CAP_NET_BIND_SERVICE`, granted two ways:

1. **File capability** baked into the binary via `setcap` during the
   image build. Survives `--cap-drop=ALL`.
2. **Compose-level `cap_add: NET_BIND_SERVICE`** in the example
   compose file. Belt-and-braces — if a future image build forgets
   `setcap`, the orchestrator still gives the daemon what it needs.

Everything else is dropped. The compose file sets `cap_drop: [ALL]`
and `security_opt: [no-new-privileges:true]` to make setuid
escalation impossible from inside the container.

## File system

The container runs with `read_only: true`. The only writable surfaces:

| Path | Backing | Why writable |
|------|---------|--------------|
| `/tmp` | tmpfs, 16 MiB, mode `1777` | rustls + tokio occasionally need scratch |
| `/var/lib/rustydns` | tmpfs (compose) or RW volume | Currently unused; reserved for future on-disk state |

Bind mounts are read-only:

| Container path | Source | Purpose |
|----------------|--------|---------|
| `/etc/rustydns/rustydns.toml` | `./rustydns.toml` | Main config (mode 0640) |
| `/var/lib/rustydns/mesh` | `./mesh` | Signed dns-zone bundle directory (Rustynet integration) |

> **Note**: the daemon enforces a strict permission check on the
> config file at startup — it refuses to load a world-readable config.
> Make sure the host-side `rustydns.toml` is `chmod 600` or `640`
> before mounting it.

## Port exposure

The compose file publishes:

| Host port | Container port | Protocol | Notes |
|-----------|----------------|----------|-------|
| 53 | 53 | UDP | Plain DNS |
| 53 | 53 | TCP | Plain DNS (fallback / TC=1) |
| 853 | 853 | TCP | DNS-over-TLS |
| 8053 | 8053 | TCP | DNS-over-HTTPS |

**The metrics endpoint (`:9153`) is intentionally not published.** It
serves `/metrics`, `/health`, and `/queries`, and rustydnsd refuses to
bind it on a non-loopback address (see
[`operator-endpoints.md`](operator-endpoints.md)).

To scrape Prometheus metrics from outside the container, run a
sidecar in the **same network namespace** so it can reach
`localhost:9153`:

```yaml
  prom-sidecar:
    image: nginx:alpine
    network_mode: "service:rustydnsd"   # share rustydnsd's netns
    volumes:
      - ./nginx-metrics-proxy.conf:/etc/nginx/conf.d/default.conf:ro
```

…and have nginx proxy `:9090` → `127.0.0.1:9153/metrics` with whatever
authentication you want on top.

## Health checking

The image has a `HEALTHCHECK` that probes
`http://127.0.0.1:9153/health` every 30 s. `docker ps` and `docker
compose ps` will surface `healthy` / `unhealthy` based on this.

The handler returns HTTP 503 if the mesh bundle is stale beyond the
`max_age_secs` configured under `[authority.mesh]`. That is the
canonical signal for "this node has fallen out of sync with the
rest of the mesh" — orchestrators should route around the container
when it goes unhealthy.

## Building your own image

```bash
docker build -t rustydnsd:local .
```

The default build uses the `Dockerfile` at the repo root. For air-gapped
builds, pre-populate `~/.cargo` and pass `--build-arg
CARGO_NET_OFFLINE=true`. (Not currently wired in; open an issue if
you need it.)

## Upgrading

```bash
git pull
docker compose build --pull
docker compose up -d
```

Compose recreates the container with the new image. The signed mesh
bundle and config file are bind-mounted, so they survive image
rebuilds untouched.

## Troubleshooting

**Container exits immediately with `permission denied` on bind**

The most common cause is a kernel/user-namespace combination where
file capabilities don't survive into the container. Confirm:

```bash
docker run --rm --entrypoint /sbin/getcap rustydnsd /usr/local/bin/rustydnsd
# expect: /usr/local/bin/rustydnsd cap_net_bind_service=ep
```

If that's empty, your storage driver stripped the xattr. Fall back to
running with `--cap-add NET_BIND_SERVICE` (the compose file already
does this) which works even without file caps.

**`/health` returns 503**

The mesh bundle is missing, malformed, or older than `max_age_secs`.
Check `/var/lib/rustydns/mesh/` on the host and confirm the publisher
is still running.

**`SERVFAIL` on every query**

Upstream DoH resolvers are unreachable. Check the container's egress
path — `docker compose exec rustydnsd wget -q --spider
https://dns.quad9.net/dns-query` is a quick probe. The non-root user's
PATH includes `/usr/bin` so `wget` and other slim utilities resolve
without absolute paths.
