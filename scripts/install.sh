#!/bin/sh
# SecretHarbor Canonical Installer for macOS and Linux
# Repository: https://github.com/logn10/SecretHarbor
#
# Usage:
#   curl -fsSL https://github.com/logn10/SecretHarbor/releases/latest/download/install.sh | sh
#   or with a pinned version:
#   curl -fsSL https://github.com/logn10/SecretHarbor/releases/download/v0.1.0/install.sh | sh -s -- --version 0.1.0

set -eu

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() {
    printf "${BLUE}==>${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}⚠️  ${NC}%s\n" "$1"
}

error() {
    printf "${RED}Error:${NC} %s\n" "$1" >&2
    exit 1
}

GITHUB_REPO="${SECRETHARBOR_GITHUB_REPO:-logn10/SecretHarbor}"
GITHUB_RELEASES="https://github.com/${GITHUB_REPO}/releases"

# 1. Detect Operating System and Architecture
detect_platform() {
    OS="$(uname -s)"
    case "$OS" in
        Darwin) OS="darwin" ;;
        Linux)  OS="linux" ;;
        *)
            error "Unsupported operating system: $OS. Download a release manually from ${GITHUB_RELEASES}"
            ;;
    esac

    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        arm64|aarch64)  ARCH="arm64" ;;
        *)
            error "Unsupported CPU architecture: $ARCH. Download a release manually from ${GITHUB_RELEASES}"
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
}

# 2. Parse Arguments
TARGET_VERSION=""
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --version|-v)
            [ $# -ge 2 ] || error "Missing value for --version"
            TARGET_VERSION="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -y|--yes)
            shift
            ;;
        *)
            warn "Unknown argument: $1"
            shift
            ;;
    esac
done

detect_platform
info "Detected platform: ${PLATFORM}"

# 3. Determine Installation Target Directory
INSTALL_DIR="${SECRETHARBOR_INSTALL_DIR:-}"
if [ -z "$INSTALL_DIR" ]; then
    if [ "$(id -u)" = "0" ] || [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="$HOME/.local/bin"
    fi
fi

# 4. Downloader
if command -v curl >/dev/null 2>&1; then
    FETCH_CMD="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
    FETCH_CMD="wget -qO-"
else
    error "Neither curl nor wget was found on your system. Please install curl or wget."
fi

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'shb-install')"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# 5. Resolve the release endpoint and version.
#    - SECRETHARBOR_UPDATE_URL set: self-hosted/mirror layout (<base>/manifest.json,
#      <base>/v<version>/<artifact>).
#    - Otherwise: GitHub Releases for GITHUB_REPO. Without --version, the version is
#      discovered from the manifest.json asset attached to the latest release.
CUSTOM_BASE="${SECRETHARBOR_UPDATE_URL:-}"
VERSION="$(echo "${TARGET_VERSION}" | sed 's/^v//')"
MANIFEST_FILE="$TMP_DIR/manifest.json"

if [ -n "$CUSTOM_BASE" ]; then
    BASE_URL="${CUSTOM_BASE%/}"
    MANIFEST_URL="${BASE_URL}/manifest.json"
    if [ -z "$VERSION" ]; then
        info "Fetching release metadata from ${MANIFEST_URL}..."
        if $FETCH_CMD "$MANIFEST_URL" > "$MANIFEST_FILE" 2>/dev/null; then
            VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST_FILE" | head -n 1)"
            VERSION="$(echo "$VERSION" | sed 's/^v//')"
        fi
        [ -n "$VERSION" ] || error "Could not determine the latest version from ${MANIFEST_URL}. Pass --version <version> explicitly."
    fi
    RELEASE_BASE="${BASE_URL}/v${VERSION}"
else
    if [ -z "$VERSION" ]; then
        MANIFEST_URL="${GITHUB_RELEASES}/latest/download/manifest.json"
        info "Fetching release metadata from ${MANIFEST_URL}..."
        if $FETCH_CMD "$MANIFEST_URL" > "$MANIFEST_FILE" 2>/dev/null; then
            VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST_FILE" | head -n 1)"
            VERSION="$(echo "$VERSION" | sed 's/^v//')"
        fi
        [ -n "$VERSION" ] || error "Could not determine the latest release version. Pass --version <version> explicitly (see ${GITHUB_RELEASES})."
        RELEASE_BASE="${GITHUB_RELEASES}/download/v${VERSION}"
    else
        RELEASE_BASE="${GITHUB_RELEASES}/download/v${VERSION}"
    fi
fi

ARTIFACT_NAME="secretharbor_${VERSION}_${OS}_${ARCH}.tar.gz"
ARTIFACT_URL="${RELEASE_BASE}/${ARTIFACT_NAME}"
CHECKSUMS_URL="${RELEASE_BASE}/checksums.txt"
DOWNLOAD_FILE="$TMP_DIR/${ARTIFACT_NAME}"

info "Release artifact: ${ARTIFACT_NAME} (v${VERSION})"
info "Download URL: ${ARTIFACT_URL}"

if [ "$DRY_RUN" = "1" ]; then
    success "Dry run complete: platform ${PLATFORM}, version ${VERSION}"
    exit 0
fi

mkdir -p "$INSTALL_DIR" || error "Failed to create installation directory: $INSTALL_DIR"

# 6. Fetch checksums and verify the archive (fail closed).
CHECKSUMS_FILE="$TMP_DIR/checksums.txt"
info "Downloading checksums from ${CHECKSUMS_URL}..."
$FETCH_CMD "$CHECKSUMS_URL" > "$CHECKSUMS_FILE" 2>/dev/null || error "Failed to download checksums from ${CHECKSUMS_URL}. Installation aborted."

EXPECTED_SHA="$(awk -v f="$ARTIFACT_NAME" '$2 == f {print $1; exit}' "$CHECKSUMS_FILE")"
if [ -z "$EXPECTED_SHA" ] && [ -s "$MANIFEST_FILE" ]; then
    EXPECTED_SHA="$(grep -A 6 "\"${PLATFORM}\"" "$MANIFEST_FILE" 2>/dev/null | sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi
[ -n "$EXPECTED_SHA" ] || error "No SHA-256 checksum published for ${ARTIFACT_NAME}. Installation aborted."

info "Downloading SecretHarbor release for ${PLATFORM}..."
$FETCH_CMD "$ARTIFACT_URL" > "$DOWNLOAD_FILE" 2>/dev/null || error "Failed to download ${ARTIFACT_URL}"

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA="$(sha256sum "$DOWNLOAD_FILE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA="$(shasum -a 256 "$DOWNLOAD_FILE" | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
    ACTUAL_SHA="$(openssl dgst -sha256 "$DOWNLOAD_FILE" | awk '{print $NF}')"
else
    error "No SHA-256 utility (sha256sum, shasum, or openssl) found. Cannot verify binary integrity."
fi

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    error "Cryptographic checksum mismatch! Expected: ${EXPECTED_SHA}, Got: ${ACTUAL_SHA}"
fi
success "Cryptographic checksum verified (SHA-256: ${ACTUAL_SHA})"

# 7. Extract and install executables atomically.
EXTRACT_DIR="$TMP_DIR/extracted"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$DOWNLOAD_FILE" -C "$EXTRACT_DIR" || error "Failed to extract release archive: ${DOWNLOAD_FILE}"

if [ ! -f "$EXTRACT_DIR/shb" ] && [ ! -f "$EXTRACT_DIR/secretharbor" ]; then
    error "Extracted archive did not contain expected binaries (shb / secretharbor)"
fi

TARGET_SHB="${INSTALL_DIR}/shb"
TARGET_SECRET_HARBOR="${INSTALL_DIR}/secretharbor"

cp -f "$EXTRACT_DIR/shb" "${TARGET_SHB}.tmp"
if [ -f "$EXTRACT_DIR/secretharbor" ]; then
    cp -f "$EXTRACT_DIR/secretharbor" "${TARGET_SECRET_HARBOR}.tmp"
else
    cp -f "$EXTRACT_DIR/shb" "${TARGET_SECRET_HARBOR}.tmp"
fi

chmod 0755 "${TARGET_SHB}.tmp" "${TARGET_SECRET_HARBOR}.tmp"
mv -f "${TARGET_SHB}.tmp" "$TARGET_SHB"
mv -f "${TARGET_SECRET_HARBOR}.tmp" "$TARGET_SECRET_HARBOR"

if [ "$OS" = "darwin" ] && command -v codesign >/dev/null 2>&1; then
    codesign -s - -f "$TARGET_SHB" 2>/dev/null || true
    codesign -s - -f "$TARGET_SECRET_HARBOR" 2>/dev/null || true
fi

# 8. Install Unix Manual Pages
MAN_DIR=""
if [ -d "/usr/local/share/man/man1" ] && [ -w "/usr/local/share/man/man1" ]; then
    MAN_DIR="/usr/local/share/man/man1"
elif [ -d "$HOME/.local/share/man/man1" ] || mkdir -p "$HOME/.local/share/man/man1" 2>/dev/null; then
    MAN_DIR="$HOME/.local/share/man/man1"
fi

if [ -n "$MAN_DIR" ] && [ -d "$EXTRACT_DIR/man/man1" ]; then
    cp -f "$EXTRACT_DIR/man/man1/"*.1 "$MAN_DIR/" 2>/dev/null || true
    info "Installed man pages to ${MAN_DIR}"
fi

# 9. Verification and Post-Install Instructions
success "SecretHarbor installed successfully!"
success "Executable: ${TARGET_SHB}"
success "Alias:      ${TARGET_SECRET_HARBOR}"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        warn "$INSTALL_DIR is not currently in your PATH."
        printf "Add it to your profile by running:\n"
        printf "  export PATH=\"%s:\$PATH\"\n\n" "$INSTALL_DIR"
        ;;
esac

if command -v "$TARGET_SHB" >/dev/null 2>&1; then
    "$TARGET_SHB" version 2>/dev/null || true
fi

printf "\nRun:\n"
printf "  shb init\n"
printf "  shb run claude\n"
