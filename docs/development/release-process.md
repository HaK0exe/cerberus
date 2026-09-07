# Release process

Cerberus releases are built from a `v*` tag on `main`. The release
workflow refuses a tag whose commit is not contained in `origin/main`,
reruns the full CI gate, and publishes cross-platform CLI archives.

## Prepare

1. Ensure the release commit is on `main` and its security-sensitive
   changes have the required two reviews.
2. Move the relevant entries from `Unreleased` to a dated, versioned
   section in `CHANGELOG.md`.
3. Run the complete gate from `AGENTS.md` and a local packaging check:

   ```bash
   make release-check
   ```

   This validates and builds the archives without publishing, signing,
   or requiring local Syft/Cosign installations. The tag workflow runs
   those supply-chain steps with pinned tool versions.

4. Extract one archive into a clean temporary directory and run
   `cerberus rules list`, `cerberus scan file <sample>`, and
   `cerberus --version` from there.

## Publish

Create an annotated tag only after the release commit is merged:

```bash
git switch main
git pull --ff-only
git tag -a v0.2.0-alpha -m "Cerberus v0.2.0-alpha"
git push origin v0.2.0-alpha
```

The workflow creates Linux, macOS, and Windows archives for amd64 and
arm64, SHA-256 checksums, SPDX and CycloneDX SBOMs, a keyless Sigstore
bundle for `checksums.txt`, and GitHub build-provenance attestations.

## Verify

Download the archive, `checksums.txt`, and its Sigstore bundle from the
GitHub release, then run:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/HaK0exe/cerberus/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum --ignore-missing -c checksums.txt
gh attestation verify cerberus_<version>_<os>_<arch>.tar.gz \
  --repo HaK0exe/cerberus
```

On macOS, use `shasum -a 256` if GNU `sha256sum` is unavailable.
