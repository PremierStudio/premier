# HTTPS Deployment and Git over SSH

This guide covers the 1-command HTTPS deployment stack (`deploy/docker-compose.yml` + `deploy/Caddyfile`) and configuring Premier's pure-Rust Git-over-SSH transport (`premier-ssh`).

## 1-Command HTTPS Deployment

Premier serves plain HTTP on port `7420`. The Compose template puts [Caddy](https://caddyserver.com/) in front of it for automatic Let's Encrypt HTTPS on ports `80` and `443`, while keeping port `7420` private to the internal Docker network.

### 1. Prepare host directories and ownership

The Premier container runs as dedicated non-root user `10001:10001`, and `/srv/repo` must be an initialized Git repository owned by that UID:

```sh
sudo mkdir -p /srv/premier/repo /srv/premier/repos /srv/premier/state
sudo git init -b main /srv/premier/repo
sudo chown -R 10001:10001 /srv/premier/repo /srv/premier/repos /srv/premier/state
```

| Host path (default) | Container path | Purpose |
| --- | --- | --- |
| `/srv/premier/repo` | `/srv/repo` | Default Git repository (working directory). |
| `/srv/premier/repos` | `/srv/repos` (`PREMIER_REPOS_DIR`) | Repositories created or imported in the Studio. |
| `/srv/premier/state` | `/var/lib/premier` (`PREMIER_STATE_DIR`) | Accounts, vaults, keys (including the SSH host key), audit logs, and agent workspaces. |

To store data somewhere other than `/srv/premier`, set `PREMIER_DATA_DIR` before starting Compose.

### 2. Set your domain and start the stack

Point your DNS `A`/`AAAA` record at the host, then start Premier and Caddy in one command:

```sh
PREMIER_DOMAIN=git.example.com docker compose -f deploy/docker-compose.yml up -d
```

- When `PREMIER_DOMAIN` is set to a public hostname (such as `git.example.com`), Caddy automatically provisions and renews TLS certificates on ports `80` and `443`.
- When `PREMIER_DOMAIN` is omitted, Caddy defaults to `localhost` with a local self-signed certificate.

### 3. How trusted proxies and streaming work

- **Trusted proxy pinning:** `deploy/docker-compose.yml` places Caddy on a fixed internal IP (`172.28.0.2` inside `172.28.0.0/24`) and sets `PREMIER_TRUSTED_PROXIES=172.28.0.2` on the `premier` service. Premier discards `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` from any peer not in `PREMIER_TRUSTED_PROXIES`, so pinning Caddy's IP gives you per-client login lockout, `Secure` session cookies, and valid Studio same-origin checks without opening header spoofing to other peers. If `172.28.0.0/24` collides with an existing network, override `PREMIER_SUBNET`, `PREMIER_CADDY_IP`, `PREMIER_APP_IP`, and `PREMIER_TRUSTED_PROXIES` together.
- **Unbuffered streaming:** `deploy/Caddyfile` configures `flush_interval -1` and disables read/write timeouts (`0s`) while relying on Caddy v2's built-in `X-Forwarded-*` headers (preserving non-default ports and multi-hop chains) so live SSE streams (audit log, approvals, agent sessions) and large Git Smart HTTP pushes (up to 512 MiB) stream cleanly without proxy buffering.
- **Bubblewrap agent sandbox:** The `premier` service includes `security_opt: ["seccomp=unconfined", "systempaths=unconfined"]` so Linux `bubblewrap` can isolate agent sessions while the server remains unprivileged (`10001:10001`). Verify with an authenticated request to `https://<your-domain>/health` (`"agent_sandbox": "bwrap"`).

---

## Git over SSH

Premier includes a pure-Rust Git-over-SSH server (`premier-ssh`) that projects every repository through the exact same access-control policy, private-branch visibility rules, and push guards as Git Smart HTTP v2.

### 1. Enable the SSH listener

By default, `deploy/docker-compose.yml` leaves SSH disabled and does not bind host port `2222` (avoiding port conflicts on hosts where SSH is unused). To enable Git over SSH with Docker Compose, include the optional `deploy/docker-compose.ssh.yml` override:

```sh
PREMIER_DOMAIN=git.example.com \
  docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.ssh.yml up -d
```

To expose a different host port (for example `22` if your host SSH daemon runs elsewhere), set `PREMIER_SSH_PORT`:

```sh
PREMIER_DOMAIN=git.example.com \
PREMIER_SSH_PORT=22 \
  docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.ssh.yml up -d
```

When running `premier` directly outside Docker, pass `--ssh-bind 0.0.0.0:2222` (or set `PREMIER_SSH_BIND=0.0.0.0:2222`). Setting `PREMIER_SSH_BIND=""` (empty) cleanly disables SSH.

The server cannot see which port Docker or your router publishes. Set `--ssh-public-url` / `PREMIER_SSH_PUBLIC_URL` (for example `ssh://git@git.example.com:22`) and `GET /v1/settings` returns it as `ssh_public_url` for the Studio's "Clone over SSH" hint.

Limits: 64 open SSH connections in total and 16 per source IP (refused before the handshake), 4 per account, one push at a time per connection. A push waits up to 30 seconds for one of the server's push slots (shared with HTTP) before any of it is accepted, then fails with `server busy: retry the push in a moment`. Revoking a key or disabling or demoting an account applies to the next Git command on an open connection.

### 2. Host key persistence

On first start with SSH enabled, Premier generates an Ed25519 host key at:

```text
<state_dir>/account/ssh_host_ed25519.key
```

(Without `--state-dir`, it is `.premier/ssh_host_ed25519.key` in the served repository.) In the Docker image (`PREMIER_STATE_DIR=/var/lib/premier`), that file is `/var/lib/premier/account/ssh_host_ed25519.key` (stored on the host at `/srv/premier/state/account/ssh_host_ed25519.key`) with owner-only `0600` permissions on Linux; on Windows it inherits the state directory's permissions. Because `/var/lib/premier` is mounted persistently, the server keeps the same SSH host fingerprint across container rebuilds and upgrades.

### 3. Generate and register an SSH public key

1. Generate an Ed25519 key pair on your workstation (if you do not already have one):

   ```sh
   ssh-keygen -t ed25519 -C "you@example.com"
   ```

2. Print your public key:

   ```sh
   cat ~/.ssh/id_ed25519.pub
   ```

3. Register the public key on your Premier account in the Studio (**Settings → SSH keys**). Only registered public keys are accepted; password, keyboard-interactive, and unauthenticated (`none`) SSH logins are always rejected.

### 4. Configure `~/.ssh/config` and run Git over SSH

Add a host block to `~/.ssh/config` so Git commands stay concise:

```sshconfig
Host premier
    HostName git.example.com
    Port 2222
    User <your-premier-username>
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
```

Clone and push using standard Git commands (Git wire protocol v2 is negotiated automatically when your client sends `GIT_PROTOCOL=version=2`):

```sh
git clone ssh://premier/notes.git
cd notes
git push origin main
```

Or without an SSH config alias:

```sh
git clone ssh://<username>@git.example.com:2222/notes.git
```

### Security boundaries

- **Public-key-only auth:** Password, `none`, and `keyboard-interactive` authentication are disabled at the SSH transport layer.
- **No shell or forwarding:** Interactive shell requests, PTY allocation, subsystems (SFTP), and TCP port forwarding are refused fail-closed.
- **Strict command allow-list:** Only `git-upload-pack` and `git-receive-pack` (plus `git upload-pack` / `git receive-pack`) with a single sanitized repository path are accepted. Shell metacharacters, extra arguments, flags, and path traversal (`..`, hidden segments) are rejected before reaching the backend.
- **Projected enforcement & caps:** Every clone, fetch, and push runs inside the authenticated user's projected repository view with the same path/branch rules, anti-oracle protections, and overlay guards as Smart HTTP, bounded to 4 MiB for SSH `git-upload-pack` requests (Smart HTTP caps `git-upload-pack` at 1 MiB) and 512 MiB for `git-receive-pack` pushes.

---

## Run under systemd (no Docker)

`deploy/premier.service` is a hardened unit for running the `premier` binary directly on Linux (`User=premier`, `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, empty capability set). Release archives (`premier-<tag>-x86_64-unknown-linux-gnu.tar.gz`, with a `.sha256` file) contain the binary, the built Studio in `ui/`, and the unit.

```sh
sha256sum -c premier-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf premier-v0.1.0-x86_64-unknown-linux-gnu.tar.gz && cd premier-v0.1.0-x86_64-unknown-linux-gnu

sudo useradd --system --home-dir /var/lib/premier --no-create-home --shell /usr/sbin/nologin premier
sudo install -m 0755 premier /usr/local/bin/premier
sudo mkdir -p /opt/premier /srv/premier/repos /etc/premier
sudo cp -r ui /opt/premier/ui
sudo git init -b main /srv/premier/repo
sudo chown -R premier:premier /srv/premier
sudo install -m 0644 premier.service /etc/systemd/system/premier.service
sudo systemctl daemon-reload && sudo systemctl enable --now premier
```

- **Paths.** The unit uses `/srv/premier/repo` (default repository, working directory), `/srv/premier/repos` (`PREMIER_REPOS_DIR`), `/var/lib/premier` (`PREMIER_STATE_DIR`, created by `StateDirectory=` with mode `0700`) and `/opt/premier/ui` (`PREMIER_STATIC_UI_DIR`). `ReadWritePaths=/srv/premier` is the only writable path outside the state directory; extend it if you keep repositories elsewhere.
- **Configuration.** Put overrides and secrets in `/etc/premier/premier.env` (`EnvironmentFile=-/etc/premier/premier.env`, optional, keep it `root:premier` `0640`), for example `PREMIER_TRUSTED_PROXIES=127.0.0.1`, `PREMIER_SSH_BIND=127.0.0.1:2222`, `PREMIER_KMS_URI=...`. To change the command line, use `sudo systemctl edit premier` and reset `ExecStart=` first.
- **TLS.** The unit binds `127.0.0.1:7420`. Terminate TLS in a reverse proxy (see the Caddy setup above) and pin it with `PREMIER_TRUSTED_PROXIES`.
- **Agent sandbox.** Install `bubblewrap`. The unit deliberately does not set `RestrictNamespaces=`, `ProtectProc=` or a syscall filter, because bubblewrap needs an unprivileged user namespace and a fresh `/proc`. If your distribution disables unprivileged user namespaces, `/health` reports `agent_sandbox: "none"`.
- **Logs.** `journalctl -u premier -f`.

## Logging, health and metrics

- **Structured logs.** `premier serve --log-format json` (the unit's default) writes one JSON object per event to stderr, ready for journald or a log shipper.
- **`GET /livez`**: liveness. Returns `200` JSON as long as the process is serving; it checks no dependencies. Used by the Docker `HEALTHCHECK` (which falls back to `/health`).
- **`GET /readyz`**: readiness. Returns `200` JSON when the server can take traffic (control-plane store and state directory usable) and a non-2xx status otherwise. Point load balancers and orchestrator readiness probes here.
- **`GET /health`**: the long-standing health endpoint. With an authenticated owner request it also reports `agent_sandbox` (`"bwrap"` or `"none"`) and `agent_sandbox_detail`.
- **`GET /metrics`**: Prometheus text exposition (`# HELP` / `# TYPE` lines, `premier_*` series). Scrape it from inside your network and do not publish it through the public reverse proxy.
- **OIDC discovery.** `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json` publish the EdDSA (Ed25519, `OKP`) workload-token verification keys. They are public by design and cacheable.
- **Response hardening.** Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a `Referrer-Policy`, a `Content-Security-Policy` and an `X-Request-Id` (quote it when reporting a problem; it matches the log line for that request). Authentication and expensive endpoints are rate limited.

Verify a running deployment end to end (read-only requests only):

```sh
pnpm --dir apps/web test:smoke                        # defaults to http://127.0.0.1:7420
PREMIER_URL=https://git.example.com node apps/web/tests/smoke-live.mjs
```

## Backup and restore

All state lives in `PREMIER_STATE_DIR` (accounts, vaults, keys, audit logs, the SQLite control-plane database) plus the repositories themselves. Take a consistent per-repository archive with the CLI, or from the Studio (**Settings → Workspace → Download backup**):

```sh
premier --state-dir /var/lib/premier backup --out /var/backups/premier/notes-$(date +%F).tar.gz
```

Restore it into an empty workspace, then start the server against it:

```sh
premier --state-dir /var/lib/premier restore /var/backups/premier/notes-2026-01-01.tar.gz --into /srv/premier/repos/notes
sudo systemctl restart premier
```

`restore` refuses to overwrite existing state unless you pass `--force`. Store archives off the host: they contain the vault's wrapped data keys, and offline-encrypted material cannot be revoked after a copy leaves your control, so treat a backup like the live vault and rotate secrets (`premier env rotate`) after a suspected leak. Back up the state directory only while the server is stopped, or use the commands above, because the control plane runs SQLite in WAL mode and a plain file copy of a live database can miss the `-wal` file.

## Windows

There is no official Windows service wrapper; run `premier.exe` from the release `.zip` (it contains `premier.exe`, `ui\`, and the licenses) under a service manager of your choice. The agent sandbox (`bubblewrap`) is Linux-only, so on Windows agent sessions are refused unless you start the server with `--allow-unsandboxed-agents` / `PREMIER_ALLOW_UNSANDBOXED_AGENTS=1`.

**Task Scheduler (no extra software).** Run once from an elevated PowerShell, adjusting the paths:

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Premier\premier.exe" `
  -Argument "--state-dir C:\Premier\state serve --bind 127.0.0.1:7420 --log-format json" `
  -WorkingDirectory "C:\Premier\repo"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "Premier" -Action $action -Trigger $trigger -Settings $settings `
  -User "NT AUTHORITY\SYSTEM" -RunLevel Highest
```

Set `PREMIER_STATIC_UI_DIR=C:\Premier\ui` as a machine environment variable (or place `ui\` where `apps\web\dist` would be under the repository). Use a dedicated low-privilege account instead of `SYSTEM` where you can, and grant it write access to `C:\Premier\state` and the repository only.

**Service wrapper.** [NSSM](https://nssm.cc/) (`nssm install Premier C:\Premier\premier.exe ...`) or WinSW run the same command line as a proper Windows service with restart-on-failure and log rotation.

Probe it the same way as on Linux: `Invoke-RestMethod http://127.0.0.1:7420/readyz`.
