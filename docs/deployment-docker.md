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

Then point a client at the host on port 53 (UDP/TCP), 853 TCP (DoT),
853 UDP (DoQ — opt-in, see compose port comment), or 8053 TCP (DoH).
DoT and DoQ share a port number but use different transport protocols (TCP vs UDP)
and therefore different sockets — they can both be enabled simultaneously.

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
assigned by Debian). The only capability it needs is
`CAP_NET_BIND_SERVICE`, and only at **startup**, to bind the
privileged listen ports (`:53`, `:853`). The daemon drops **all**
capabilities in-process immediately after the initial bind (the
`caps` crate clears every set, including the bounding set), so for
the entire steady-state lifetime of the process it holds **no**
capabilities — a later bug or compromise cannot re-bind a privileged
port. (This is also why live SIGHUP listener handover is offered only
for unprivileged ports — see [`docs/security.md`](security.md)
§"Linux Capabilities".) The startup capability is granted two ways:

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
| `/var/lib/rustynet` | `./mesh` | Signed dns-zone bundle + verifier key (Rustynet integration); matches the example config's paths |

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
| 853 | 853 | UDP | DNS-over-QUIC (RFC 9250) — opt-in; uncomment the mapping when `doq_listen` is set |
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

## Verify it's working

After `docker compose up -d`, walk through these in order — if any
step fails, jump to the matching row in
[Troubleshooting](#troubleshooting).

```bash
# 1. Container is up and the healthcheck has gone green.
docker compose ps
#   NAME         STATUS                    PORTS
#   rustydnsd    Up 2 minutes (healthy)    0.0.0.0:53->53/udp, ...

# 2. /health on the host (compose publishes :9153 only inside the
#    container; reach it through docker exec or a sidecar in the
#    same netns — see "Port exposure" above).
docker compose exec rustydnsd bash -c 'exec 3<>/dev/tcp/127.0.0.1/9153; printf "GET /health HTTP/1.0\r\n\r\n" >&3; cat <&3'
#   {"status":"ok"}

# 3. A normal name resolves through the daemon (host-side test).
dig @127.0.0.1 example.com +short
#   93.184.216.34

# 4. A known ad/tracker domain is blocked.
dig @127.0.0.1 doubleclick.net +short
#   (empty — status: NXDOMAIN if you use `dig +noshort`)

# 5. The blocklist hit counter increments.
docker compose exec rustydnsd bash -c 'exec 3<>/dev/tcp/127.0.0.1/9153; \
    printf "GET /metrics HTTP/1.0\r\n\r\n" >&3; grep blocklist_hits_total <&3'
#   rustydns_blocklist_hits_total 1
```

If step 5's counter rose by 1 between steps 3 and 4, ads are being
blocked end-to-end. Point your router or per-device DNS at the host
running rustydnsd and the same filtering applies network-wide.

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

503 means the readiness flag has not flipped yet: not every configured
listener is bound. It is transient during startup — if it persists,
`docker compose logs rustydnsd` shows the failing bind (port already in
use, missing TLS material, invalid config value, …). Note that `/health`
is liveness ONLY by design: mesh-bundle staleness deliberately does not
flip it (see docs/operator-endpoints.md).

**Mesh names don't resolve (daemon otherwise healthy)**

A missing, stale, or signature-failed bundle drops the authority to
static-only mode with a warn ("mesh bundle could not be loaded", later
"mesh zone reload failed") — the last-good snapshot keeps serving until a
good reload succeeds. The tell is `rustydns_mesh_zone_last_reload_seconds`
going stale on /metrics plus `rustydns_mesh_zone_reload_failure_total`
climbing. Check that ./mesh/ contains dns-zone.bundle +
dns-zone-verifier.key matching the paths in your config.

**`SERVFAIL` on every query**

Upstream DoH resolvers are unreachable. Check the container's egress
path — the image is debian-slim, which deliberately ships no wget/curl,
so probe with bash's built-in /dev/tcp instead:

```bash
docker compose exec rustydnsd bash -c 'exec 3<>/dev/tcp/9.9.9.9/443 && echo egress-ok'
```
