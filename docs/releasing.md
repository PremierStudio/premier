# Premier release packaging

Premier release archives are reproducible wrappers around a single executable
that already embeds the production viewer. Packaging adds `README.md`, the
Apache-2.0 `LICENSE`, machine-readable `RELEASE-METADATA`, internal
`SHA256SUMS`, and an archive checksum sidecar. Official GitHub releases also
include keyless Sigstore bundles, an authenticated aggregate checksum manifest,
SPDX SBOMs, and GitHub build-provenance attestations.

## Supported binary matrix

| Operating system | Architecture | Rust target | Packaging | Installation |
| --- | --- | --- | --- | --- |
| macOS 13+ | Apple silicon | `aarch64-apple-darwin` | supported | supported |
| macOS 13+ | Intel | `x86_64-apple-darwin` | supported | supported |
| Linux (glibc) | x86-64 | `x86_64-unknown-linux-gnu` | supported | supported |
| Linux (glibc) | ARM64 | `aarch64-unknown-linux-gnu` | supported | supported |

Windows and musl targets are not currently packaged. A native runner can build
its own target directly. For cross compilation, the release job must first
produce a compatible binary and pass it through `--binary`; the packaging
script does not pretend to provision cross-linkers or SDKs.

## Produce an archive

On a native runner, build the viewer and release binary together:

```sh
./scripts/package-release.sh --target aarch64-apple-darwin --version 0.1.0
```

To package a binary built by an earlier CI step:

```sh
./scripts/package-release.sh \
  --target x86_64-unknown-linux-gnu \
  --version 0.1.0 \
  --binary ./target/x86_64-unknown-linux-gnu/release/premier
```

The tar stream has sorted paths, normalized ownership and modes, and zeroed
timestamps; gzip also has a zero timestamp. Identical inputs therefore produce
identical archives and checksums.

## Signed public release workflow

`.github/workflows/release.yml` is the only public signing path. It runs only
for version tags, requires the protected `release` environment, builds the
native target matrix, runs the full Rust suite, packages reproducible archives,
and generates SPDX SBOMs. Its publication job has narrowly scoped `contents`,
`id-token`, and `attestations` permissions.

The publication job creates deterministic `SHA256SUMS`, signs both that manifest
and every archive with keyless Sigstore, immediately verifies the pinned GitHub
workflow identity and OIDC issuer, creates build-provenance attestations, and
publishes the immutable asset set to GitHub Releases. It then extracts the four
verified native executables into platform-specific npm packages and publishes
those packages, `@premierstudio/trace`, and the `@premierstudio/premier`
launcher through npm trusted publishing with provenance. Pull requests and
branch builds cannot obtain the release signing identity or npm publication
trust.

The npm launcher and platform packages intentionally have no `preinstall`,
`install`, or `postinstall` lifecycle scripts. npm selects a platform package as
an optional dependency; package installation never downloads an executable from
an arbitrary URL and works with npm 12's secure install-time defaults.

Before enabling the public channel, repository administrators must protect the
`v*` tag namespace, require approval for the `release` environment, and give
every published package on npmjs.com a GitHub Actions trusted publisher pinned
to `PremierStudio/premier`, workflow `release.yml`, environment `release`.
That link cannot be observed locally, so the release workflow exposes a
manual preflight: dispatching **Signed release** from the Actions tab runs
only `verify-npm-trusted-publishing`, which performs the same OIDC token
exchange `npm publish` will use for all six packages without publishing
anything. Run it before pushing a tag; a tag push repeats the preflight and
publishes nothing — no GitHub release, no npm packages — until it passes. CI
also rehearses the preflight's token exchange against a stub OIDC issuer and
registry (`scripts/tests/preflight-npm-trusted-publishing.test.mjs`), so a
regression in that flow fails pull requests instead of tag pushes. macOS
code signing and notarization remain a separate Gatekeeper requirement; Sigstore
authenticates the downloaded release asset but is not Apple notarization.

## Consumer workflow

The primary consumer path is npm:

```sh
npm install --global @premierstudio/premier
premier --version
```

For a project-local, version-pinned toolchain:

```sh
npm install --save-dev @premierstudio/premier
npx premier record -- npm test
```

The signed archive path below is the Node-free alternative.

Download an archive and its sibling `.sigstore.json` bundle, then install by
explicit path. The installer verifies the archive against the pinned
`PremierStudio/premier` release workflow and GitHub Actions OIDC issuer
before extraction:

```sh
./scripts/install.sh \
  --archive ./premier-0.1.0-aarch64-apple-darwin.tar.gz \
  --signature-bundle ./premier-0.1.0-aarch64-apple-darwin.tar.gz.sigstore.json
```

To authenticate a complete downloaded release set in one operation, verify the
signed aggregate manifest:

```sh
./scripts/verify-release.sh --directory ./downloaded-release
```

Unsigned archives are rejected by default. `--allow-unsigned` exists only for a
locally produced developer archive and prints an explicit warning; it is never
part of the public installation path.

The installer rejects absolute/traversal archive paths, links and device files,
foreign architectures by default, missing metadata, missing required payloads,
and checksum mismatches. It stages extraction outside the destination and
renames the validated executable into place atomically.
