# Premier control plane (Studio UI + Rust binary).
# The repo itself is mounted at /srv/repo so git history and policy stay on disk across image
# rebuilds; the server's own state (accounts, vault, keys, audit log) lives in /var/lib/premier,
# outside every repository. The Studio UI is built here and baked into the image.
FROM node:22-bookworm-slim AS web
WORKDIR /web
# pnpm 10 reads apps/web/pnpm-lock.yaml (lockfileVersion 9.0). pnpm 9 rejects the checked-in
# pnpm-workspace.yaml ("packages field missing or empty"), so do not pin it lower.
RUN npm install -g pnpm@10
COPY apps/web/package.json apps/web/pnpm-lock.yaml apps/web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY apps/web ./
RUN pnpm build

# cargo-chef caches the compiled dependency graph in its own layer: the recipe only changes when
# a Cargo.toml / Cargo.lock does, so source-only edits rebuild just the workspace crates.
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /src

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json -p premier-cli
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p premier-cli

FROM debian:bookworm-slim
# bubblewrap is the agent-session sandbox. It needs namespaces and a fresh /proc, which Docker's
# defaults deny (see the run options below): without them `premier serve` reports
# `agent_sandbox: "none"` with the reason in `agent_sandbox_detail`, and refuses sessions (or
# set PREMIER_ALLOW_UNSANDBOXED_AGENTS=1 to run them unconfined).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl bubblewrap \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/premier /usr/local/bin/premier
COPY --from=web /web/dist /opt/premier/ui
# The server never runs as root: a dedicated user with a fixed uid/gid, so bind mounts can be
# given to it by number (`chown -R 10001:10001`). Git refuses to operate on a repository owned
# by another user, so /srv/repo and /srv/repos must belong to it.
RUN groupadd --gid 10001 premier \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/premier --no-create-home \
        --shell /usr/sbin/nologin premier \
    && mkdir -p /var/lib/premier /srv/repo /srv/repos \
    && chown 10001:10001 /var/lib/premier /srv/repo /srv/repos \
    && chmod 700 /var/lib/premier
# `premier serve` serves this baked UI; without the variable it falls back to <workspace>/apps/web/dist.
ENV PREMIER_STATIC_UI_DIR=/opt/premier/ui
# Repositories created or imported from the Studio; the default one stays at /srv/repo.
ENV PREMIER_REPOS_DIR=/srv/repos
# ALL server state: accounts, per-repository vaults and keys, approvals, sessions, audit logs,
# agent session workspaces. Never inside a repository's working tree, where a pushed commit
# could be checked out over it. Mount a named volume or a host directory here, or the state is
# lost with the container.
ENV PREMIER_STATE_DIR=/var/lib/premier
ENV HOME=/var/lib/premier
VOLUME /var/lib/premier
VOLUME /srv/repos
EXPOSE 7420
EXPOSE 2222
USER 10001:10001
WORKDIR /srv/repo
# To give agent sessions the bubblewrap sandbox, run the container with BOTH
#   --security-opt seccomp=unconfined --security-opt systempaths=unconfined
# (compose: `security_opt: ["seccomp=unconfined", "systempaths=unconfined"]`). The server is an
# unprivileged user, so bwrap builds the sandbox in a user namespace of its own: Docker's
# default seccomp profile blocks the unprivileged namespace syscalls that takes, and its masked
# /proc paths stop the sandbox from mounting a /proc of its own. With both, `/health` reports
# `agent_sandbox: "bwrap"`; with only the first, the startup probe fails the same way a session
# would and says so in `agent_sandbox_detail`. Neither option makes the server or the agent
# root. A session sees an allow-list of the image (/usr, the CA certificates) and its own
# workspace, and has no network but its own egress proxy.
#
# Liveness probe: `/livez` (process is serving, no dependency checks), falling back to `/health`
# for servers that predate it. Use `/readyz` for orchestrator readiness gates, not this check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:7420/livez || curl -fsS http://127.0.0.1:7420/health || exit 1
CMD ["premier", "serve", "--bind", "0.0.0.0:7420"]
