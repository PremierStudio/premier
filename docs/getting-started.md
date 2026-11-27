# Getting started

This walks through a first run: your owner account, a repository, a second person, and a rule that gives them access to part of it.

It assumes the server is running and reachable at `http://<host>:7420`. If it is not, follow the quick start in the [README](../README.md) or the [admin guide](admin-guide.md).

## 1. Create the owner account

Open the server in a browser. A server with no accounts shows **Create the owner account**.

- **Username**: 2–32 characters, lowercase letters, digits, `_` or `-`.
- **Password**: at least 10 characters.

The first account is an owner. Owners manage users, policy, secrets and approvals. Whoever reaches this page first becomes the owner, so do this before you expose the server to anyone else.

Your principal, the name policy rules use for you, is `@<username>`.

## 2. Turn on two-factor

Two-factor adds a 6-digit code from an authenticator app (TOTP) after your password.

1. Go to **Settings → Two-factor authentication** and choose **Set up two-factor**.
2. Scan the QR code with your authenticator app, or type in the key shown next to it.
3. Enter the 6-digit code the app shows and choose **Turn on two-factor**.
4. Save the recovery codes that appear. There are ten. Each works once, in place of the 6-digit code, and they are not shown again.

You can replace the codes later with **Generate new codes**. That needs your password and invalidates the old set.

Once two-factor is on, `git` no longer accepts your account password. Use an access token instead (next step).

If you lose both the app and the codes, see [account recovery](admin-guide.md#account-recovery-from-the-host).

## 3. Create an access token

An access token is the password you give `git`.

1. Go to **Settings → Access tokens**.
2. Enter a **Token name**, for example `laptop git`, pick an expiry, and choose **Create token**.
3. Copy the token. It starts with `prm_` and is shown once.

Revoke a token from the same list to cut that client off.

## 4. Create a repository

Open the repository menu in the top bar and choose **New repository…**.

- **Name**: 1–63 characters of `a-z`, `0-9`, `.`, `_` or `-`, starting with a letter or digit. It may not end in `.git`, and `repo` and `auth` are reserved.
- **Description**: optional.
- **Import from URL (https)**: optional. Leave it empty for an empty repository.

### A new, empty repository

The Studio shows **This repository is empty** with two commands. Run them in the folder of the project you want to push:

```sh
git remote add premier http://<username>@<host>:7420/git/auth/<name>.git
git push -u premier main
```

`git` asks for a password. Paste the access token. Then choose **I've pushed, refresh**.

### Importing from a URL

Give an `https://` URL, for example `https://github.com/owner/project.git`. The server clones it. A large project can take a few minutes; keep the tab open.

Only plain `https://` URLs to public hosts are accepted. Private and tailnet addresses are refused unless the server was started with `--allow-private-imports`. The server sends no credentials, so the source must be readable without signing in.

**An imported repository's own `.access.toml` is not enforced.** If the project you import contains a policy file, Premier keeps the file but applies the built-in owner-only policy instead, and shows a notice:

> The imported repository contained its own access policy, which has NOT been activated. Review it under Policy and save to apply.

Open the **Policy** tab, read the imported rules, change what you need, and choose **Commit & apply**. Until you do, only owners have access.

## 5. Add a member

1. Go to **Settings → Users**.
2. Enter a **Username** and an **Initial password**, leave the role as member, and create the account.
3. Give the person the password. They should change it under **Settings → Password** after they sign in.

Members act only as themselves. They cannot manage users, change the policy, read the audit log, or set secrets.

A new member can sign in but sees no repository yet. The starter policy grants access to owners only.

## 6. Give the member access

Say the member is `mia` and you want her to read and change everything under `docs/`.

Open the **Policy** tab. It shows the repository's `.access.toml`. Add a rule below the existing one:

```toml
[[rules]]
id = "mia-docs"
effect = "allow"
principals = ["@mia"]
paths = ["docs/**"]
capabilities = ["traverse", "list", "read", "write"]
reason = "Mia maintains the documentation"
```

Choose **Compute Diff** to see what the change does, then **Commit & apply**. The server compiles the policy, commits it to the default branch and uses it from the next request on. No restart is needed.

To grant by group instead, put Mia in a group under **Settings → People & groups** (edit `@mia`, add a group such as `docs`) and use `principals = ["group:docs"]` in the rule. See the [policy guide](policy-guide.md).

## 7. Check the rule with "View as"

Before you tell Mia, look at the repository the way she will.

1. In the top bar, open **View as** and pick `@mia`. This is a simulator: you stay signed in as yourself. Only owners have it.
2. Open the **Code** tab. The tree now holds only what Mia's rules allow. Here that is `docs/` and its contents.
3. Switch the tree from **Strict** to **X-Ray** to also see what is hidden from her, marked as omitted.
4. Select a file to see the **Capability Matrix**: the capabilities she has on it and the rules that produced them. Type any path into **Explain path…** and choose **Eval** to test a path that is not in front of you.

Switch **View as** back to yourself when you are done.

## 8. What the member sees

**In the Studio.** Mia signs in and sees only the repositories she can enter. In this one, the tree shows `docs/` and nothing else. The names of the other files and directories are never sent to her browser. She has no **View as**, cannot apply a policy, and the owner-only sections of Settings are closed to her.

**Over Git.** Mia creates her own access token and clones:

```sh
git clone http://mia@<host>:7420/git/auth/<name>.git
```

Her clone contains the commits and files under `docs/` only. Hidden files are not in her history at all, not as names and not as object IDs. Because her commits carry different trees from yours, commit IDs in her clone can differ from the ones in your clone.

She can commit and push changes under `docs/`. The server puts the hidden files back when it records her commit, so nobody else loses anything. A push that touches a path she may not write is rejected with `policy denied WRITE on '<path>' for @mia`.

A branch Mia creates by pushing is visible only to her until an owner changes its visibility in the **Branches** tab.

## 9. Work from the command line

The `premier` CLI ([install it](../README.md#install-the-premier-cli)) prepares your own projects and keeps personal files out of shared history.

- `premier init` in a project directory runs `git init -b main` if needed and writes a starter `.access.toml` and `.env.schema`. It is safe to run again: existing files are left alone. Commit both files; the server enforces the versions on the default branch.
- `premier overlay mount <path> --file <local file>` mounts a personal overlay (add `--scope team:<name>` for a team one). Overlay content is stored encrypted in the state directory, and `premier overlay check-push <paths...>` exits 1 if a commit would publish one. `premier overlay list` and `premier overlay unmount <path>` manage them.

## Next

- [Policy guide](policy-guide.md) for the rule format and more examples.
- [Admin guide](admin-guide.md) for HTTPS, backups and recovery.
- [Security](security.md) for what this does and does not protect.
