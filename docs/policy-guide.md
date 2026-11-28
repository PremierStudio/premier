# Policy guide

A policy says who may do what to which paths, on which branches. It is a TOML file named `.access.toml` at the root of a repository. This guide describes the format as the server parses it, then gives worked examples.

## Where the policy comes from

Each repository has its own `.access.toml`. The server reads it from the **tip of the default branch**, not from any file on disk, and reloads it whenever that branch moves.

What that means in practice:

- Saving the policy in the Studio's **Policy** tab (**Commit & apply**) commits `.access.toml` to the default branch and applies it.
- An owner can also change it with `git push`. The push is checked first: the file must load, and it must leave the owners able to read and write it. A push from anyone who is not an owner that changes `.access.toml` or `.env.schema` is refused.
- A repository with no `.access.toml` on its default branch gets the built-in starter policy below. So does an imported repository, until an owner reviews its policy and applies it.

### The starter policy

```toml
# Premier starter policy: only owners have access. Add rules below.
# Everyone else, including anonymous Git clones, gets nothing until a rule grants it.
version = 1

[defaults]
public = []
authenticated = []

[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
reason = "Workspace owners have full access; nobody else has any until rules grant it"
```

Every owner account is in the group `owners` automatically. The name is reserved; you cannot put anyone else in it.

## The file format

```toml
version = 1

[defaults]
public = []                 # capabilities for everyone, signed in or not
authenticated = []          # extra capabilities for everyone signed in

[zones.billing]             # optional: a named set of paths
paths = ["billing/**"]
exclude = ["billing/README.md"]

[[rules]]                   # any number of rules
id = "billing-team"
effect = "allow"            # "allow" or "deny"
principals = ["group:billing"]
paths = ["billing/**"]      # path globs, and/or
zones = ["billing"]         # zone names
refs = ["main"]             # optional: branches the rule applies on
capabilities = ["traverse", "list", "read", "write"]
reason = "Shown in the Studio next to the rule"

[[agent_profiles]]          # optional: limits for AI agent sessions
name = "ui-agent"
allow_paths = ["apps/web/**"]
deny_paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]
allow_secret_use = ["STRIPE_API_KEY"]
allow_egress_hosts = ["registry.npmjs.org"]

[quarantine]                # optional: agent instruction files
instruction_files = ["AGENTS.md", "CLAUDE.md"]
```

A rule needs an `id`, an `effect`, and at least one entry in `paths` or `zones`. A rule that names a zone that is not defined is an error, and so is an unknown capability name. The server refuses to apply a policy that does not compile.

## Principals

A principal is who a rule applies to. These selectors are recognised:

| Selector | Matches |
| --- | --- |
| `@mia` or `user:mia` | The account `mia`. |
| `group:docs` or `team:docs` | Everyone in the group `docs`. |
| `authenticated` | Everyone signed in. |
| `anonymous` or `public` | Callers with no credentials, such as an anonymous `git clone`. |
| `*` | Everyone, signed in or not. |
| `agent:*`, `agent:ui-agent` | An agent session with any profile, or with the named profile. Only works in `deny` rules. |
| `bot:name`, `service:name` | Parsed, but no client can sign in as a bot or a service today. |

Groups are assigned by an owner under **Settings → People & groups**. Group membership always comes from that directory, never from the request. A selector the server does not recognise matches nobody.

## Capabilities

| Capability | What it gives |
| --- | --- |
| `traverse` | Pass through a directory to reach something below it. The directory appears; its other contents do not. |
| `list` | The path's name appears in the Studio tree. |
| `read` | The file's contents. A file is included in a Git clone only with `read`. |
| `write` | Add, change or delete the path by pushing. |
| `use` | For secrets: let a brokered request carry the secret. Never reveals the value. |

`*` or `all` in a capability list means all five.

Details that matter:

- **`traverse` is granted for you.** If a rule allows you anything on `docs/guides/setup.md`, you get `traverse` on `docs` and `docs/guides` automatically. You see those two directories and that one file. You do not see their other contents.
- **A path with no capability is omitted entirely.** Its name, its size and its Git object ID are not sent.
- **`write` needs `read`.** A push that adds a file you would not be able to read back is rejected.
- **For a directory to appear in a clone**, you need `traverse`, `list` or `read` on each directory above the file, and `read` on the file. The automatic `traverse` normally covers the directories.

## How rules combine

For one person, one path and one branch, the server collects every rule that matches and works out the result in this order:

1. Start with `[defaults]`: `public`, plus `authenticated` if the caller is signed in.
2. Add what the repository's `allow` rules grant.
3. Remove what the repository's `deny` rules name. **Deny overrides allow**, whatever order the rules are written in.
4. Add what the server policy's `allow` rules grant.
5. Remove what the server policy's `deny` rules name.

Rule order in the file never matters.

A `deny` for `*` applies to owners too. If you write "deny `finance/**` to `*`" and then "allow `finance/**` to `group:owners`", the owners are still denied, because deny wins inside one file. Deny narrower groups instead, or do not grant the path in the first place.

### Server policy over repository policy

A server policy is a second file in the same format, given to the server at startup with `--server-policy`. It applies to every repository and cannot be edited from the Studio, where it shows as a read-only **Server Policy** tab.

It overrides the repository's file in both directions: a server `allow` grants access even where the repository denies it, and a server `deny` removes access no matter what else allows it. Use it for rules that a repository's own policy must not be able to undo.

Only `rules`, `agent_profiles` and `quarantine` are read from the server policy. `[defaults]` always come from the repository's file. Zones are local to the file that defines them.

```toml
version = 1

[[rules]]
id = "org-hard-deny-master-key"
effect = "deny"
principals = ["*"]
paths = ["billing/ledger/master.key"]
capabilities = ["traverse", "list", "read", "write", "use"]
reason = "Server policy forbids direct key access regardless of in-repo rules"
```

## Path globs

Paths are relative to the repository root and use `/`. A leading `/` is ignored.

| Pattern | Matches |
| --- | --- |
| `README.md` | That file. |
| `docs/*` | Entries directly inside `docs`. Not `docs/private/x`. |
| `docs/**` | Everything under `docs`, at any depth. |
| `**/secrets.yml` | A `secrets.yml` in any directory. |
| `**` | Every path. |
| `*` | Every entry at the top level of the repository. |
| `{apps,libs}/**` | Everything under `apps` or under `libs`. |

`*` and `?` never cross a `/`. Only `**` does. `[abc]` character classes work, and a backslash escapes the next character.

## Branch scoping

`refs` limits a rule to some branches. It takes globs over the short branch name, such as `main` or `release/1.0`.

- Leave `refs` out, or write `refs = ["*"]`, and the rule applies on every branch.
- `refs = ["release/*"]` matches `release/1.0` but not `release/a/b` and not `main`.
- `refs = ["**"]` also means every branch.

`refs` decides which rules apply on a branch. It does not hide the branch. Whether someone can see a branch at all is a separate setting, the branch's visibility, which an owner sets in the **Branches** tab:

| Visibility | Who can see the branch |
| --- | --- |
| public | Anyone who can see the repository. |
| org | Everyone signed in. |
| restricted | The listed principals and groups. |
| personal | One person. |

A branch you cannot see is not advertised to your Git client and its commits cannot be fetched. A new branch pushed by an owner is public, unless it was built from a branch that is not, in which case it takes that branch's visibility. A new branch pushed by a member is personal until an owner changes it.

## Zones

A zone is a name for a set of paths, so several rules can refer to it.

```toml
[zones.billing]
paths = ["billing/**", "libs/invoicing/**"]
exclude = ["billing/README.md"]

[[rules]]
id = "billing-team"
effect = "allow"
principals = ["group:billing"]
zones = ["billing"]
capabilities = ["traverse", "list", "read", "write"]
```

A rule that names a zone covers the zone's `paths`. If the rule names any zone with an `exclude` list, those excluded paths are removed from everything the rule covers, including its own `paths`. A zone may also carry `owners` and `description`; the server stores them but does not act on them.

Zones also give secrets a home: a secret declared with `zone = "billing"` in `.env.schema` is addressed as `secrets/billing/<NAME>`.

## Agent profiles

An agent session runs on behalf of a person, with a profile. Its access is the **intersection** of what the person may do and what the profile allows. A profile can narrow a person's access. It can never widen it.

| Field | Meaning |
| --- | --- |
| `name` | The profile's name. A session uses `ui-agent` unless the request names another. |
| `allow_paths` | Path globs the agent may touch. Anything else is denied. |
| `deny_paths` | Path globs removed from `allow_paths`. |
| `capabilities` | What the agent gets on allowed paths. |
| `allow_secret_use` | Secret names the agent may `use`. `"*"` means any. |
| `allow_egress_hosts` | Extra hosts the proxy lets through, on port 443, for `premier agent run` and `premier proxy start`. Sessions started from the Studio do not read this field: their proxy passes only the hosts declared in `.env.schema`. |

Rules that hold whatever the profile says:

- A session that names a profile the policy does not define gets nothing.
- An agent never gets `read` on a secret. The most it can get is `use`.
- A profile defined in a repository's policy cannot `write` to `.access.toml`, `.env.schema`, `.github/workflows/**`, `AGENTS.md` or `CLAUDE.md`. A profile defined in the server policy can.
- A server-policy profile replaces a repository profile of the same name.
- A `deny` rule with `principals = ["agent:*"]` or `["agent:<profile>"]` removes capabilities from agent sessions only.

## Quarantined instruction files

Files such as `AGENTS.md` and `CLAUDE.md` are instructions that an AI agent will follow, so a change to one deserves the same care as a change to code. `[quarantine]` lists which files count. If you leave it out, the list is:

```toml
[quarantine]
instruction_files = [
  "AGENTS.md",
  "CLAUDE.md",
  ".cursorrules",
  ".github/copilot-instructions.md",
  "**/AGENTS.md",
  "**/CLAUDE.md",
]
```

The server blocks changes to these files; it does not merely flag them. An agent session's commit that touches one is refused (`quarantine blocked change to instruction file ...`). A member's edit to one in the Studio is not applied but held for an owner to approve or reject (`hold_pending_for_non_owners`, on by default). `enforce = false` turns the block off. The files are marked **Quarantined** in the Studio's Code tab, and the Policy tab's impact diff raises an alert when a change touches one. You can also pin a file to a SHA-256 hash, and the diff reports a mismatch as critical:

```toml
[quarantine.pinned_hashes]
"AGENTS.md" = "<sha-256 of the approved file, in hex>"
```

## Worked examples

Each example is added to the starter policy, so owners keep full access.

### 1. Read-only docs for everyone signed in

```toml
[[rules]]
id = "docs-for-signed-in"
effect = "allow"
principals = ["authenticated"]
paths = ["docs/**", "README.md"]
capabilities = ["traverse", "list", "read"]
```

Every account can now enter the repository and sees `README.md` and `docs/`. Nobody but owners can push to them. Anonymous clones still get nothing.

### 2. A private directory

The staff may work on everything. Contractors may work on everything except `finance/`.

```toml
[[rules]]
id = "staff-everything"
effect = "allow"
principals = ["group:staff", "group:contractors"]
paths = ["**"]
capabilities = ["traverse", "list", "read", "write"]

[[rules]]
id = "contractors-no-finance"
effect = "deny"
principals = ["group:contractors"]
paths = ["finance/**"]
capabilities = ["*"]
reason = "Finance is staff only"
```

A contractor's clone has no `finance/` directory and no trace of its history. Do not write the deny for `*`: that would lock out staff and owners as well.

### 3. A team-only branch

You want a branch `launch-v3` that only the launch team can see, and on which they can change the pricing page that is otherwise read-only.

First make the branch invisible to everyone else. In the **Branches** tab choose **New Private Branch** and name it `launch-v3`. Then select the branch and add `group:launch` under **Authorized Principals**.

Then scope the extra write access to that branch:

```toml
[[rules]]
id = "launch-team-pricing"
effect = "allow"
principals = ["group:launch"]
paths = ["site/pricing/**"]
refs = ["launch-v3"]
capabilities = ["traverse", "list", "read", "write"]
```

The visibility hides the branch. The rule decides what the team may do on it. Members of `group:launch` still need rules that let them read the rest of the tree, as on any other branch.

### 4. A release branch nobody pushes to by accident

```toml
[[rules]]
id = "release-frozen"
effect = "deny"
principals = ["group:staff"]
paths = ["**"]
refs = ["release/*"]
capabilities = ["write"]
reason = "Release branches are changed by owners only"
```

Staff keep `read` on `release/1.0` and lose `write` there. On `main` the rule does not apply.

### 5. A secret an agent may use but nobody may read

Declare the secret in `.env.schema`, with the only place it may be sent:

```toml
version = 1

[vars.STRIPE_API_KEY]
type = "secret"
sensitivity = "restricted"
zone = "billing"

[vars.STRIPE_API_KEY.egress]
hosts = ["api.stripe.com"]
methods = ["GET", "POST"]
path_prefixes = ["/v1/"]
inject = { kind = "bearer_header", header = "Authorization" }
approval = "jit"
```

An owner stores the value in the **Secrets** tab. Then, in `.access.toml`:

```toml
[[rules]]
id = "secrets-never-read"
effect = "deny"
principals = ["*"]
paths = ["secrets/**"]
capabilities = ["read"]

[[agent_profiles]]
name = "ui-agent"
allow_paths = ["apps/web/**"]
capabilities = ["traverse", "list", "read", "write"]
allow_secret_use = ["STRIPE_API_KEY"]
```

The secret's address is `secrets/billing/STRIPE_API_KEY` (it would be `secrets/STRIPE_API_KEY` without a zone). Owners have `use` on it through the starter rule. The `deny` removes `read` for everyone. The profile lists the secret, so an agent session started by an owner may `use` it.

In the session, the environment variable `STRIPE_API_KEY` holds a placeholder, not the key. When the agent calls `https://api.stripe.com/v1/...` through the session's proxy, the proxy puts the real key in the `Authorization` header. A request to any other host, method or path does not get it. `approval = "jit"` makes the first use wait until an owner approves it in the **Agents** tab. The approval then holds for a limited time (`jit_ttl_secs`, 300 seconds unless you set it).

`.env.schema` is read from the tip of the default branch, like the policy, and reloaded whenever that branch moves.

## How to check your rule

Check before you rely on a rule. There are three tools, all for owners.

**View as.** In the top bar, open **View as** and pick a person, a person combined with the `ui-agent` profile, or `anonymous`. The Studio then shows the repository as that identity would see it. The list comes from **Settings → People & groups**, so you can add a principal there to test with before the person has an account. `Shift+L` cycles through the list.

**X-Ray and explain.** In the **Code** tab, switch the tree from **Strict** to **X-Ray** to show the entries that are hidden from the identity you are viewing as. Select an entry to open the **Capability Matrix**: it shows the effective capabilities and each rule that matched, with its layer (repo or server), its effect and its reason. To test a path that is not in the tree, type it into **Explain path…** and choose **Eval**.

**Impact diff.** In the **Policy** tab, edit the policy and choose **Compute Diff** before you apply it. The diff lists, for each principal and path under **Probes**, which capabilities the change grants and which it revokes. Add the people and paths you care about as probes. **Commit & apply** commits the policy to the default branch and applies it.

From a shell on the server you can ask the same question of a policy file. Group membership is passed on the command line here, because the CLI does not read the server's directory:

```sh
premier access explain @mia docs/guide.md --group docs --ref main --policy .access.toml
premier access check --policy .access.toml
```

## Limits

A policy may hold up to 4096 rules and 256 agent profiles. One rule may hold up to 256 patterns, and one pattern up to 512 characters.
