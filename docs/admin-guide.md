# Admin guide

How to install, run, back up and repair a Premier server.

## Installation

Premier is one binary, `premier`, that serves the API, Git and the Studio on one port. The supported way to run it is the Docker image, `ghcr.io/premierstudio/premier:latest`, published with every release. To build it yourself instead, run `docker build -t premier .` in this repository and use `premier` as the image name below. The [README quick start](../README.md#quick-start) runs the image on named volumes with no `sudo`; this section uses host directories, which is easier to back up and inspect.

### Docker

```sh
docker pull ghcr.io/premierstudio/premier:latest

sudo mkdir -p /srv/premier/repo /srv/premier/repos /srv/premier/state
sudo git init -b main /srv/premier/repo
sudo chown -R 10001:10001 /srv/premier/repo /srv/premier/repos /srv/premier/state

docker run -d --name premier -p 7420:7420 \
  -v /srv/premier/repo:/srv/repo \
  -v /srv/premier/repos:/srv/repos \
  -v /srv/premier/state:/var/lib/premier \
  ghcr.io/premierstudio/premier:latest
```

What the image fixes:

| Thing | Value |
| --- | --- |
| Working directory, and the default repository | `/srv/repo` |
| Repositories created or imported from the Studio | `/srv/repos` (`PREMIER_REPOS_DIR`, a declared volume) |
| All server state | `/var/lib/premier` (`PREMIER_STATE_DIR`, a declared volume) |
| Studio files | `/opt/premier/ui` (`PREMIER_STATIC_UI_DIR`) |
| Port | `7420` (HTTP), `2222` (optional Git-over-SSH when `--ssh-bind` / `PREMIER_SSH_BIND` is set) |
| Command | `premier serve --bind 0.0.0.0:7420` |
| Health check | `curl -fsS http://127.0.0.1:7420/health` every 30 seconds |
| User | `premier`, uid and gid `10001`, home `/var/lib/premier`. Never root. |

Mount all three directories. Without a mount on `/var/lib/premier`, the accounts, vaults, keys and audit logs live in an anonymous volume that is not carried to a new container. Without one on `/srv/repo`, the default repository is lost with the container. A named volume (`-v premier-state:/var/lib/premier`) works as well as a host directory.

`/srv/repo` must be a Git repository before the server starts; Premier does not create it.

**Ownership.** The server runs as uid `10001`, and Git refuses to work in a repository owned by a different user. Every directory you bind-mount must belong to that uid: `chown -R 10001:10001` on the repository, the repos directory and the state directory, as above. A new named volume gets the right owner by itself.

The host paths under `/srv/premier` are examples.

Started like this, the server refuses agent sessions: their sandbox needs two more `docker run` options. See [Docker and seccomp](#docker-and-seccomp).

### `premier serve` options

To pass options, append the full command to `docker run`, or set the environment variable where one exists.

| Flag | Environment variable | Default | What it does |
| --- | --- | --- | --- |
| `--bind <addr:port>` | | `127.0.0.1:7420` | Address to listen on. The image passes `0.0.0.0:7420`. |
| `--policy <file>` | | `.access.toml` | The working-copy policy file that a backup includes. The server does not read its policy from it: see [where the policy comes from](#where-the-policy-comes-from). |
| `--server-policy <file>` | | none | A policy that overrides every repository's own. See the [policy guide](policy-guide.md#server-policy-over-repository-policy). |
| `--schema <file>` | | `.env.schema` | Ignored. The secret schema is the `.env.schema` committed on the default branch. |
| `--state-dir <dir>` | `PREMIER_STATE_DIR` | none | Keep all server state in this directory instead of inside the repositories' working trees. The image sets `/var/lib/premier`. See [where data lives](#where-data-lives). Also read by `premier restore` and `premier auth`. |
| `--audit <file>` | | `.premier-local/audit.jsonl`, or `<state dir>/repos/<id>/audit.jsonl` | The default repository's audit log. |
| `--trusted-proxy <ip>` | `PREMIER_TRUSTED_PROXIES` | none | IP address of a reverse proxy whose `X-Forwarded-*` headers are believed. Repeat the flag, or separate addresses with commas. |
| `--name <name>` | | the directory name | Name of the default repository. In the image the directory is `repo`, which is a reserved name, so the default repository is called `default`. |
| `--repos-dir <dir>` | `PREMIER_REPOS_DIR` | `.premier/repos`, or `<state dir>/worktrees` | Where other repositories live. The image sets `/srv/repos`. |
| `--allow-unsandboxed-agents` | `PREMIER_ALLOW_UNSANDBOXED_AGENTS` | off | Run agent sessions without a sandbox when the host has none. See [agent sessions](#agent-sessions-and-the-sandbox). |
| `--allow-private-imports` | `PREMIER_ALLOW_PRIVATE_IMPORTS` | off | Let repository imports fetch from private, CGNAT (tailnet) and IPv6 unique-local addresses. |
| `--ssh-bind <addr:port>` | `PREMIER_SSH_BIND` | none | Optional address for the pure-Rust Git-over-SSH listener (e.g. `0.0.0.0:2222`). Leaving it unset or empty disables SSH. See [SSH & HTTPS deployment](ssh-and-deploy.md). |

Relative paths are resolved against the directory the server starts in. `PREMIER_STATIC_UI_DIR` has no flag: it names the directory holding the built Studio, and without it the server looks for `apps/web/dist` under its working directory. Log verbosity follows `RUST_LOG` and defaults to `info`.

Example, with a name and a trusted proxy (the address is an example; see [HTTPS and reverse proxies](#https-and-reverse-proxies) for how to find yours):

```sh
docker run -d --name premier -p 7420:7420 \
  -v /srv/premier/repo:/srv/repo \
  -v /srv/premier/repos:/srv/repos \
  -v /srv/premier/state:/var/lib/premier \
  -e PREMIER_TRUSTED_PROXIES=172.17.0.1 \
  ghcr.io/premierstudio/premier:latest premier serve --bind 0.0.0.0:7420 --name home
```

## Where data lives

A repository's content and the server's own state are kept apart. The repositories are Git working trees: `/srv/repo` and `/srv/repos/<name>` in the image. The state is in the **state directory**, `--state-dir` or `PREMIER_STATE_DIR`: `/var/lib/premier` in the image.

**Run a server with a state directory.** It exists because a repository's working tree is something other people push into. With the state outside it, no pushed commit can ever be checked out over the account file, a vault or a key. The names `.premier`, `.premier-local` and `.git`, and every spelling a filesystem treats as one of them, are refused as path components in pushes, publishes, Studio edits and agent-session commits either way.

**Account-wide state**, in `<state dir>/account/`:

| File | Contents |
| --- | --- |
| `premier.db` | SQLite database (WAL mode): accounts, password hashes, two-factor secrets, sessions, access-token hashes, registered SSH public keys, security events. |
| `premier.db-wal`, `premier.db-shm` | SQLite's write-ahead log and shared-memory index. They belong to `premier.db`: copy or delete all three together, never one alone. |
| `auth.key` | AES-256-GCM key that encrypts the two-factor secrets inside `premier.db` (`0600`). Without it, two-factor cannot be verified. |
| `oidc.key` | Ed25519 key that signs OIDC workload tokens, unless `PREMIER_OIDC_SIGNING_KEY` is set. |
| `directory.json` | Principals and their groups. |
| `repos.json` | Descriptions and creation dates of the repositories. |
| `ssh_host_ed25519.key` | Ed25519 SSH host key generated on first start with `--ssh-bind` / `PREMIER_SSH_BIND` (`0600`). |

**Per-repository state**, in `<state dir>/repos/<id>/`. The id is a random value the server writes once into the repository's `.git/premier-id`, so renaming a repository (or serving it under another `--name`) keeps its vault and settings, and a new repository created under an old name starts fresh. `<state dir>/repo-index.json` maps names to ids for people reading the directory; the server does not use it to find state. In the image the default repository is called `default` unless you pass `--name`.

| File | Contents |
| --- | --- |
| `premier.db` (+ `-wal`, `-shm`) | SQLite database (`repo_state` table): branch visibility, reviews, overlays, secret metadata. The default repository's also holds the workspace settings (audit retention). |
| `vault.toml` | Secret values, encrypted. |
| `age.key` | The key that decrypts the vault. |
| `approvals.json` | Agent approvals. |
| `sessions.json` | Recent agent sessions. |
| `audit.jsonl` | The audit log. |
| `imported-policy-pending` | Marker: the policy that came with an import is not enforced yet. |
| `session-workspaces/` | The private workspaces of agent sessions. One is removed when its session is committed or discarded, or 24 hours after it ended. |

**Older layouts.** Servers before the SQLite store kept accounts in `account/auth.json` and repository state in `state.json`. The server imports them into `premier.db` the first time it needs them and from then on reads only the database. It deletes `auth.json` once the import is durable, because that file held two-factor secrets in plain form; a leftover `state.json` is ignored and can be removed after you have checked the upgrade.

The state directory is made owner-only (0700) at startup, and state files are written with owner-only permissions (0600) on Linux.

**In each repository's directory** there is only the repository:

| Path | Contents |
| --- | --- |
| `.git` and the working copy | The full, unfiltered history. Branches that are not public are stored under `refs/premier-private/`, the others under `refs/heads/`; a caller who may see one gets it as `refs/heads/<name>`. |
| `.access.toml` | The repository's policy, as committed on the default branch. |
| `.env.schema` | The secret schema, as committed on the default branch. |

The working copy follows the default branch when a push, publish or edit moves it, but only when that is safe: the tree had no local changes, the new commit names no reserved path, and it would not write over a file Git ignores. Otherwise the working copy is left as it is and the server logs a warning; the server never reads content from it.

### Moving to a state directory

An older server kept its state inside the working trees: `.premier/` and `.premier-local/audit.jsonl` in each repository's directory, and the other repositories under `.premier/repos` unless `--repos-dir` said otherwise.

The first time a server starts with a state directory, it moves that state there and logs one line listing what moved. It does this per repository, and only when the state directory has nothing for that repository yet. It never merges: once the state directory holds state, a `.premier` that appears in a working tree is ignored.

If `--repos-dir` is not set and `.premier/repos` exists, that directory is moved to `<state dir>/worktrees`. This is a rename, so it needs the state directory on the same filesystem; if it is not, the server stops and tells you to move the directory yourself or pass `--repos-dir`. The image sets `--repos-dir`, so this does not arise there.

With the image, the move happens on the first start of the new image. The server now runs as uid `10001` and must be able to read and remove the old files, so run the `chown -R 10001:10001` from [Docker](#docker) before that start.

### Without a state directory

`premier serve` without `--state-dir` keeps the old layout: `.premier/` and `.premier-local/audit.jsonl` inside each repository's directory, as listed above but under those two names, and agent workspaces in a randomly named, owner-only directory under the system temporary directory. This is for running against a local checkout. In this mode the server never updates the working copy, because its own files are in it.

Every Git working tree directly under the repos directory with a valid name is loaded as a repository at startup.

### Where the policy comes from

The server enforces the `.access.toml`, and uses the `.env.schema`, that are **committed at the tip of the repository's default branch** (the branch its `HEAD` names). It does not read either from the working copy, and `premier serve` has no option that points it at another file.

- With no `.access.toml` committed there, the built-in owner-only policy applies. With no `.env.schema`, there is no schema.
- With no default branch at all (a detached `HEAD` in the server's repository), the built-in owner-only policy applies as well, whatever is committed, and every push is judged under it. Attach `HEAD` to a branch again (`git checkout <branch>` in the repository's directory) and restart the server.
- A commit that changes either file on the default branch takes effect as soon as the branch moves. It can arrive by a save in the **Policy** tab, a file edit in the Studio, a `git push`, a publish, or a committed agent session. In every case only an owner may make it, from a browser session for all but the push, and the server refuses a policy that does not parse, does not compile under the server policy, or would take `read` or `write` on `.access.toml` away from the group `owners`.
- On any other branch the two files are ordinary files and change nothing until they reach the default branch.
- If the committed policy or schema is broken when the server starts, the server stops with the reason.

The working copy only follows the default branch, and only when that is safe. See [where data lives](#where-data-lives).

## HTTPS and reverse proxies

Premier speaks plain HTTP. For HTTPS, put a TLS-terminating reverse proxy in front of it, such as Tailscale Serve, Caddy or nginx, forwarding to port 7420.

Tell Premier the proxy's address with `--trusted-proxy` or `PREMIER_TRUSTED_PROXIES`. The value is the IP address the server sees the proxy connect from. With Docker's default bridge network that is usually the bridge gateway, not `127.0.0.1`. To find it, sign in once through the proxy and look at **Settings → Security activity**: the address on the newest entry is what the server sees.

Only a trusted proxy's `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` are read. From any other peer they are discarded. This matters for three things:

- **Lockout.** Failed sign-ins are counted per client address. If the proxy is not trusted, every user appears to come from the proxy's address. One person's wrong passwords then count against everyone, and twenty failures lock out all sign-ins through the proxy for up to 15 minutes.
- **Secure cookies.** The session cookie gets the `Secure` attribute only when a trusted proxy reports `X-Forwarded-Proto: https`. Without that, the cookie is sent without `Secure` even though the browser used HTTPS.
- **The same-origin check.** A change made from the browser must come from the server's own origin. The server compares the request's `Origin` with `Host`, or with `X-Forwarded-Host` from a trusted proxy. If your proxy rewrites `Host` and is not trusted, every change from the Studio fails with `cross-origin request rejected`.

Do not list an address that untrusted clients can also connect from. Anyone connecting from a trusted address can claim any client address.

## Users and roles

There are two roles. The first account is an owner. Accounts created under **Settings → Users** are members unless you choose owner.

Members can sign in, browse and search what the policy lets them read, edit files where the policy gives them `write`, create branches from branches they can see, take part in reviews, and manage their own profile, password, two-factor, sessions and access tokens.

An edit in the Studio is a commit. Saving or deleting a file writes one commit on the selected branch, authored by the signed-in account. Nothing is left uncommitted in the server's working copy.

Only owners can:

- Create, change, disable and delete user accounts, and reset another user's password.
- Edit principals and groups under **People & groups**.
- Change a repository's policy or secret schema, in the **Policy** tab or by committing `.access.toml` or `.env.schema` on the default branch.
- Use **View as**, X-Ray, the rule explanation and the policy impact diff.
- Set and delete secrets, and see secret status.
- Read and export the audit log.
- Change workspace settings and download backups.
- Start agent sessions, commit or discard what they changed, and decide approvals.
- Mount and unmount overlays.
- Publish a private branch, delete a branch, and change a branch's visibility.
- Create, describe and delete repositories.

Owners are subject to the policy like everyone else. The starter policy gives the group `owners` everything; if you remove that rule or write a `deny` that matches owners, owners lose that access too.

The server always keeps at least one enabled owner: you cannot demote, disable or delete the last one, and you cannot delete your own account. Disabling an account ends its sessions and refuses its access tokens, but keeps them. Deleting an account removes its sessions, tokens and group memberships.

## Access tokens

A token stands in for a password where a browser session is not available. Create one under **Settings → Access tokens**. It starts with `prm_`, is shown once, and can expire in 30, 90 or 365 days or never. Only a hash is stored.

**Git.** Use your username and the token as the password:

```sh
git clone http://<username>@<host>:7420/git/auth/<name>.git
```

- `/git/auth/<name>.git` always asks for credentials.
- `/git/<name>.git` serves the anonymous view if no credentials are sent, and your own view if they are. Pushing always needs an account.
- The default repository also answers at `/git/auth/repo.git` and `/git/repo.git`.

Your account password works for Git too, but only while two-factor is off. With two-factor on, Git is told `two-factor is enabled: use an access token as the password`.

**API.** Send the token as a bearer token. Routes for a repository other than the default are prefixed with `/r/<name>`.

```sh
curl -H "Authorization: Bearer prm_..." http://<host>:7420/v1/repos
curl -H "Authorization: Bearer prm_..." http://<host>:7420/r/notes/v1/branches
```

**What a token cannot do.** These need a browser session and answer `requires a browser session` to a token:

- Anything under account management: passwords, two-factor, sessions, tokens.
- **Everything only an owner may do.** Every owner-only action is also browser-only; there is no owner-only route a token can call. That covers: saving a policy in the **Policy** tab; setting or deleting a secret; deciding an agent approval; starting an agent session, and committing or discarding what one changed; publishing a branch, changing a branch's visibility, deleting a branch; mounting or unmounting an overlay; reading or exporting the audit log; changing workspace settings; downloading a backup; managing users and the directory; creating, changing or deleting a repository.
- Writing or deleting `.access.toml` or `.env.schema` through the file API, on any branch.

A stolen token therefore cannot take over the account, administer the server or get a shell. It can still do what its account may do as a member would: read, edit other files, create branches, review, and use Git.

**The one exception is `git push`.** Git has no browser session, so an owner's token can push a commit that changes `.access.toml` or `.env.schema` on the default branch. The server checks it exactly as it checks a save in the Studio (it must load, and must leave the owners in) and records the push in the audit log with the account that pushed.

## Sessions and lockout

A browser session ends after 30 days without use. **Settings → Sessions** lists yours and lets you sign out the others.

Five wrong passwords for one username from one address block that username from that address. Twenty wrong passwords from one address, across all usernames, block the address. Either block lasts up to 15 minutes. The message is `Too many attempts. Try again in N minutes.` A wrong two-factor code counts as a failure. The counters are held in memory, so restarting the server clears them.

## Audit log

Each repository has an audit log, `audit.jsonl` in its part of the state directory, one JSON event per line. It records pushes, policy changes, secret changes, agent sessions, proxy decisions and backup downloads. Events carry the account that made the request, including when an owner was using **View as**.

- **View** it in the **Agents** tab, with search and a filter by decision.
- **Export** it with **Export audit log** under **Settings → Workspace**. You get the whole file as `premier-audit-<date>.jsonl`, for the repository currently selected.
- **Retention**: set **Keep audit events for (days)** under **Settings → Workspace**, from 1 to 3650, or **Keep forever**. The default is forever. Older events are dropped when the server starts and once a day after that. The setting applies to every repository.

Sign-ins and account changes are recorded separately and shown under **Settings → Security activity**. The server keeps the most recent 200.

## Backup and restore

### Taking a backup

Select a repository, go to **Settings → Workspace** and choose **Download backup**. You get `premier-backup-<date>.tar.gz`.

**Each repository is backed up separately.** A backup covers the repository that was selected when you downloaded it. Back up the default repository to capture the accounts, and each other repository for its own history and secrets.

The archive contains:

- `.premier/`: that repository's state. It holds a consistent snapshot of the repository's `premier.db`. For the default repository it also includes the account data (a snapshot of the account `premier.db` with users, sessions, tokens and registered SSH public keys, plus `auth.key`, `directory.json`, `repos.json`, and `ssh_host_ed25519.key` when SSH has been enabled). It always includes `vault.toml` **and `age.key`, the key that decrypts it**. Agent session workspaces are not included.
- `.premier-local/audit.jsonl`: the audit log.

These two names are the archive's own. They are the same whether the server keeps its state in a state directory or not, so an archive from an older server restores onto a newer one.

- `repo.bundle`: a Git bundle of every ref, private branches included.
- `workspace/`: the working-copy `.access.toml` and `.env.schema`. The ones the server enforces are the committed ones, which are in the bundle.

**Anyone who has the archive can read every secret in it and the full, unfiltered history. The default repository's archive also holds the password hashes and two-factor secrets.** Store it accordingly.

The archive is built in memory. That is fine for a home-server repository; a very large one needs that much free RAM.

### Restoring

`premier restore` unpacks an archive into a directory:

```sh
premier restore premier-backup-2026-01-31.tar.gz --into /srv/repo
```

- If the directory has no `.git`, the repository is recreated from the bundle with all its refs, and its HEAD is checked out. If it has one, the existing repository is left alone.
- The state files are restored: into the state directory when `--state-dir` or `PREMIER_STATE_DIR` is set (accounts to `<state dir>/account/`, the rest to `<state dir>/repos/<name>/`, which the server moves to the repository's id the next time it starts), otherwise into `.premier` and `.premier-local` in the directory. The name is the directory's name, as `premier serve` derives it; pass `--name` if you serve the repository under another. If that repository already has state there, or the archive carries account files and accounts already exist, the command stops unless you pass `--force`.
- The policy and schema files are written last. If one already exists and differs from the backup, the command stops unless you pass `--force`.

`--into` defaults to the current directory. The command needs `git` on the path.

With Docker, stop the server and run the restore in a one-off container:

```sh
docker stop premier
docker run --rm \
  -v /srv/premier/repo:/srv/repo \
  -v /srv/premier/state:/var/lib/premier \
  -v "$PWD/premier-backup-2026-01-31.tar.gz:/backup.tar.gz:ro" \
  ghcr.io/premierstudio/premier:latest premier restore /backup.tar.gz --into /srv/repo
docker start premier
```

The image sets `PREMIER_STATE_DIR`, so the state goes to the mounted state directory. The archive must be readable by uid `10001`.

To restore a repository other than the default, restore its archive into `<repos dir>/<name>` (in the image, `/srv/repos/<name>`) and start the server. It loads every repository it finds there.

## Account recovery from the host

If you cannot sign in, fix the account from a shell on the server. Both commands act on the accounts in the state directory (`PREMIER_STATE_DIR`, which the image sets), or without one on those of the current directory, which must then be the default repository.

**Reset a password.** The new password is read from standard input. It must be at least 10 characters. Every session of that account is signed out. Access tokens are kept.

```sh
docker exec -i premier premier auth reset-password <username>
```

Type the password and press Enter.

**Turn off two-factor** when the authenticator and the recovery codes are both lost. This also discards the recovery codes.

```sh
docker exec premier premier auth disable-totp <username>
```

The running server picks up both changes at once. Each is recorded under **Security activity** as recovered with the CLI.

## Agent sessions and the sandbox

An agent session runs a command on the server, in a private copy of one branch. Owners start them from the **Agents** tab.

The session never runs in the repository. The server writes a workspace for it that holds only the files its identity may read on that branch. That identity is the person the session runs as, narrowed by the agent profile: it may do only what both may. The workspace is a small Git repository with one commit and no history, so `git status` and `git diff` work in it. A file the identity may not read is not there in any form.

The command gets:

- An empty environment plus `PATH`, `LANG` and `TERM`, a throwaway home directory, and placeholder tokens in place of secrets.
- A local proxy, set as `HTTP_PROXY` and `HTTPS_PROXY`, that swaps a placeholder for the real secret only on requests the schema allows, and otherwise lets through only the hosts the agent profile lists under `allow_egress_hosts`.
- Output scrubbing: any secret value that appears in the command's output is redacted before it is stored or shown.

A session is killed at its time limit: 30 minutes unless the request asks for another, and never more than 4 hours. The server keeps the 30 most recent sessions and the last 250 lines of output of each.

### Committing what a session changed

Nothing a session does reaches the repository by itself. When it ends, the server compares the workspace with what it started as and shows the change set: files added, modified and deleted. An owner then commits it or discards it.

- A commit is one commit on the branch the session started from, authored by the owner who commits it. The default message is `Agent session <id>`.
- Every path in the change set needs `write` for the session's identity. If one is denied, nothing is committed. What the agent profile may not write stays unwritten even when the owner could write it.
- The branch must still be at the commit the session started from. If it moved, the commit is refused and nothing is applied.
- A change to `.access.toml` or `.env.schema` on the default branch is checked as described under [where the policy comes from](#where-the-policy-comes-from).
- A change set with more than 2000 paths, a new file over 8 MiB or more than 64 MiB of changes in total is shown but cannot be committed. The same goes for a workspace that holds more than 1 GiB of files when the session ends, a device, FIFO or socket, or a file with more than one hard link. The server checks sizes before it reads anything and reads at most 1 GiB to work out a change set.
- A path with a reserved component (`.premier`, `.premier-local`, `.git`, or a spelling a filesystem treats as one) refuses the commit.
- Executable bits are kept. A symbolic link is never followed: it is committed as a link, with its target text, and only if that target is relative and stays inside the workspace. A link of the branch whose target leads outside is not put in the workspace, and a link the agent makes with an absolute or outside target is not committed; both are listed on the session as skipped, and the branch keeps what it has at those paths. A server on Windows makes no links at all, and files there keep the executable bit they had on the branch.

An uncommitted workspace is removed 24 hours after its session ended.

### bubblewrap

On Linux the session runs inside [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`), which the image installs. Inside it:

- The filesystem is an **allow-list**, not the host with parts removed. It holds, read-only, `/usr`, `/bin`, `/sbin`, `/lib` and `/lib64` (those that exist), `/etc/ssl`, `/etc/ca-certificates` and `/etc/alternatives`, plus an `/etc/passwd` and `/etc/group` the server generates with two entries. Nothing else of the host or the container is there: not the rest of `/etc` (no `/etc/shadow`, no TLS keys), not the state directory, not any repository, not a `--server-policy` file, not `/root`, `/home`, `/run` (so no Docker socket) or `/var`, and no other volume.
- `/tmp` is private: it holds the workspace at `/tmp/workspace`, the only writable directory that outlives the session, and a fresh home at `/tmp/home`. Everything outside `/tmp` is read-only.
- The process IDs are its own, with its own `/proc`. The server's process and its environment cannot be seen.
- There is **no network** except loopback. The only way out is a relay to the session's own proxy, so a request that does not go through the proxy has nowhere to go. There is no DNS inside and no `/etc/resolv.conf`; clients hand the host name to the proxy.
- The command runs as an unprivileged user (uid 1000) in its own user namespace. Where the host forbids user namespaces, bubblewrap can only run the command as the server's own user with every capability dropped, and `agent_sandbox_detail` says so. **If that user is root, the server refuses sessions instead**, unless you pass `--allow-unsandboxed-agents`. The image runs the server as uid `10001`, so this refusal concerns servers you start as root yourself.

A tool the agent needs must be under `/usr` in the image. See [security](security.md) for what the sandbox does not cover.

### Docker and seccomp

bubblewrap needs to create namespaces as an unprivileged user and to mount a `/proc` of its own. Docker's defaults deny both, so run the container with **both** of these options:

```sh
docker run -d --name premier -p 7420:7420 \
  --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined \
  -v /srv/premier/repo:/srv/repo \
  -v /srv/premier/repos:/srv/repos \
  -v /srv/premier/state:/var/lib/premier \
  ghcr.io/premierstudio/premier:latest
```

In Compose: `security_opt: ["seccomp=unconfined", "systempaths=unconfined"]`. The first turns off Docker's system-call filter for the container, the second its masking of paths under `/proc` and `/sys`. Both apply to the whole container, not only to sessions. Neither makes the server or an agent root: the server stays uid `10001`.

Without them bubblewrap is installed but does not work, and the server refuses agent sessions with:

> agent sessions need a sandbox and this host has none that works (bubblewrap on Linux); start the server with --allow-unsandboxed-agents to run them as a plain process of the server user

The server tests the sandbox once at startup, with the same arguments a session gets, and logs the result as `agent_sandbox`. A signed-in request to `/health` reports it too:

```sh
curl -H "Authorization: Bearer prm_..." http://<host>:7420/health
```

`"agent_sandbox": "bwrap"` means the sandbox works. `"none"` means sessions are refused. `"unsandboxed-allowed"` means they run without one. `agent_sandbox_detail` gives the reason when it is not `bwrap`.

You have two choices: run the container with the two options, or accept running without a sandbox.

### `--allow-unsandboxed-agents`

With `--allow-unsandboxed-agents` or `PREMIER_ALLOW_UNSANDBOXED_AGENTS=1`, a host without a working sandbox runs sessions as a plain process of the server user. The session still starts in its private workspace, the environment is still scrubbed, secrets are still placeholders, and its changes still need an owner's commit. The session is marked as not confined.

**What you risk:** the command can read every file the server user can. That includes the state directory (the account file, every vault and its key), files the policy hides from the session's identity, and every repository in full. It can also write those files, and it can open network connections that do not go through the proxy. Use it only for commands you would run on the server yourself.

The flag has no effect where bubblewrap works.

## Upgrading

All data is in the three mounted directories, so an upgrade replaces the container and keeps the data.

```sh
docker pull ghcr.io/premierstudio/premier:latest
docker stop premier && docker rm premier
docker run -d --name premier -p 7420:7420 \
  -v /srv/premier/repo:/srv/repo \
  -v /srv/premier/repos:/srv/repos \
  -v /srv/premier/state:/var/lib/premier \
  ghcr.io/premierstudio/premier:latest
```

**Coming from an image that ran as root and had no state directory**, do this once, between stopping the old container and starting the new one:

```sh
sudo mkdir -p /srv/premier/state
sudo chown -R 10001:10001 /srv/premier/repo /srv/premier/repos /srv/premier/state
```

On its first start the new server moves the state out of the repositories into `/srv/premier/state`. See [moving to a state directory](#moving-to-a-state-directory). Scripts that used an owner's access token for an owner-only action (reading the audit log, for example) now get `requires a browser session`.

Download a backup of each repository first. Repeat any extra options you started the old container with. Agent sessions that are running when the server stops are marked `interrupted`. Browser sessions and access tokens survive the restart.

## Troubleshooting

**"Too many attempts. Try again in N minutes."** You are locked out by failed sign-ins from your address. Wait, or restart the server to clear the counters. If this happens to everyone at once, the server is behind a proxy that is not listed in `--trusted-proxy`.

**Forgotten password.** Another owner can set a new one under **Settings → Users**. If there is no other owner, use `premier auth reset-password` as shown above.

**Lost authenticator.** Enter a recovery code in the same field as the 6-digit code. Each works once. If the codes are gone too, use `premier auth disable-totp`.

**"cross-origin request rejected" on every change in the Studio.** The browser's origin does not match the `Host` the server receives. Add the reverse proxy to `--trusted-proxy`.

**"account management requires a browser session" or "this action requires a browser session".** You called a browser-only route with an access token. Do it in the Studio.

**Git keeps asking for a password.** Use an access token, not the account password, if two-factor is on. Check the token has not expired or been revoked.

**"repository not found" for a repository that exists.** The caller cannot see anything in it. The server gives the same answer as for a name that does not exist. Grant the person access, or use the `/git/auth/` URL so Git sends credentials.

**Push rejected.** Git prints the reason after `! [remote rejected]`:

| Message | Cause and fix |
| --- | --- |
| `not a fast-forward of the server's branch: force-push is only allowed for owners or on your personal branch` | The branch moved on the server, possibly with commits you cannot see. Fetch, merge with `git merge --no-ff`, and push again. Non-fast-forward force-pushes (`git push --force-with-lease`) are allowed only for repository owners or on your own personal branch (preserving hidden files from the canonical tip untouched). |
| `policy denied WRITE on '<path>' for <you>` | You lack `write` on that path on this branch, or the path collides with something hidden from you. Ask an owner for a rule. |
| `'<path>' cannot be pushed: it would not be readable by you on this branch` | You added a file you have no `read` on. |
| `ref update rejected: fetch and retry, or check the branch and your access` | The branch or tag is not visible to you, the name is taken by a ref you cannot see, your copy is stale, another push got there first, or the push changes `.access.toml` or `.env.schema` on the default branch and you are not an owner. The message is the same for all of these on purpose. Fetch and retry; if it persists, ask an owner about the branch. |
| A message that starts with `.access.toml:` or `.env.schema:` | You are an owner and the pushed file cannot become the policy or schema: it does not parse or compile, or it would lock the owners out. The rest of the message says which. |
| `only refs/heads/<valid branch name> or refs/tags/<valid tag name> can be pushed` | You pushed a ref outside `refs/heads/*` and `refs/tags/*` (or with an invalid name). Branches and commit-targeting lightweight/annotated tags under `refs/tags/*` can be pushed; updating or deleting an existing tag is owner-only (`only repository owners may update existing tags` / `only repository owners may delete tags`). |
| `cannot delete the default branch` / `only repository owners or the branch's personal owner may delete this branch` | `git push --delete` is supported with strict compare-and-swap for repository owners or the branch's personal owner. The default branch can never be deleted. |
| `overlay guard blocked push: ...` | The push contains a path reserved for a mounted overlay. |
| `more than 10000 commits in one push; push in smaller steps` | Push the history in parts. |

One push may be at most 512 MiB on the wire, and a single file at most 100 MiB.

**Import fails with "import_url must be an https:// URL" or "import_url must name a public https host".** Imports accept only `https://` URLs to public hosts. For a source on your LAN or tailnet, start the server with `--allow-private-imports`. Loopback and link-local addresses are never allowed.

**Agent sessions are refused.** See [Docker and seccomp](#docker-and-seccomp).

**A change to `.access.toml` has no effect.** The policy is the file committed on the default branch. A change on another branch, or an uncommitted edit of the server's working copy, does nothing until it is committed there. See [where the policy comes from](#where-the-policy-comes-from).

**Publish is refused with "changed on both".** Publishing lands a branch's changes since it forked from the target as one commit on top of the target, leaving out the paths the public may not read. Non-overlapping edits to the same regular text file (with matching file modes) merge automatically via 3-way line-level merge (and the merged result is checked against private blobs). Overlapping text edits, binary files, mode mismatches, or modify/delete collisions refuse the whole publish, and nothing is published. Bring the target's version of those paths into the branch (or the other way round), then publish again. "The target branch moved while publishing" means someone else moved the target at that moment: reload and retry.

**`premier doctor`** prints what the host offers: FIFO support, bubblewrap, `unshare`, FUSE and ProjFS. Only bubblewrap matters to the server today.
