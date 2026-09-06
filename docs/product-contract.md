# Product contract

Status: locked for the bootstrap/APT proof of concept. No public release is
allowed until every release gate in this document has passed.

## Identity

- Working display name: `Prodysor Terminal`.
- Production application ID: `com.prodysor.term`.
- Private data directory: `/data/data/com.prodysor.term`.
- Home directory: `/data/data/com.prodysor.term/files/home`.
- Prefix: `/data/data/com.prodysor.term/files/usr`.
- Java namespaces remain `com.termux.*`; they are implementation namespaces,
  not the Android application ID.
- The deprecated Android `sharedUserId` is permanently removed. Drop-in Termux
  plugins are not supported; any future extension must use an explicit IPC API.
- There is no automatic migration from `com.termux`.

The application ID and prefix are accepted as permanent by the repository owner
for retained installs. Artifacts produced before the signed-repository gate are
disposable and must not be distributed. The display name and visual brand may
change before the first public release.

## Supported product

- Distribution: GitHub Releases / direct sideload only.
- First device target: Samsung Galaxy S23 Ultra on Android 16.
- First ABI: `arm64-v8a` only.
- Package variant: `apt-android-7` only.
- Target SDK: retain the pinned upstream Termux value for the POC. Raising it is
  a separate Android execution-compatibility project, not routine maintenance.
- Official Termux and Prodysor Terminal must install and operate side by side.

## Existential POC

The project proceeds only if all of the following work without binary patching:

1. A source-built ARM64 bootstrap uses the exact production prefix and is
   embedded in the APK with a checked SHA-256.
2. A minimal, independently signed APT repository publishes packages built from
   the same pinned recipes as the embedded bootstrap, including the complete
   transitive dependency closure needed for updates.
3. The bootstrap trusts only the Prodysor repository and rejects missing,
   expired, unknown, or incorrect repository signatures.
4. A fresh install starts a native dynamic executable and a shebang script.
5. `apt update`, install, interrupted-upgrade recovery, upgrade, and remove work.
6. The custom app remains isolated from an installed official Termux app.

Initial package scope is deliberately small: the bootstrap/base closure plus
`curl`, `git`, and `openssh` if their full closures are maintainable. Python,
Node.js, AI CLIs, and the wider Termux catalogue are excluded from the POC.

Stop the project and revisit the product requirement if the POC requires:

- patched official ELF binaries or shebangs;
- an official Termux binary repository;
- a second production-like package ecosystem for a debug suffix;
- mixing packages built for different prefixes;
- a dependency closure we cannot rebuild and publish from source.

## Trust and releases

- APK signing and APT repository signing use separate keys.
- Neither private key is committed or exposed to pull-request workflows.
- Each key requires an offline primary copy, two encrypted backups, a tested
  recovery procedure, and a documented fingerprint before release.
- A production-like RC uses the exact production ID, prefix, bootstrap, and APK
  signing identity. The tested APK is promoted by digest without rebuilding it.
- A `.dev` variant may use a fake shell for UI development; it must never be
  represented as a real-shell release candidate.

## MVP boundary

MVP includes a stable terminal, sessions, source-built bootstrap, curated APT
repository, safe updates, side-by-side isolation, basic tabs/themes, GPL source
compliance, and Android 16 device verification.

MVP excludes plugins, root integration, Play Store/F-Droid distribution,
multi-ABI support, telemetry, cloud sync, automatic migration, a full Compose
rewrite, automatic HOME mutation, dangerous AI defaults, and the full Termux
package catalogue.

## Repository topology

- `Prodysor/NewTermux` legacy `main` remains a donor and historical reference.
- `product/main` starts from pinned official Termux commit
  `3b66f8799635a4dba4a206563048ff0e6792c487`.
- NewTermux UI features are ported individually only after the package POC.
- Release automation stays disabled until signing and promotion gates exist.
- The product branch must not merge the unrelated legacy snapshot history.
