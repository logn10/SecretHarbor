#!/bin/sh
# SecretHarbor Canonical Installer for macOS and Linux
# Website: https://secretharbor.dev
# Documentation: https://secretharbor.dev/docs/installation
#
# Usage:
#   curl -fsSL https://secretharbor.dev/install.sh | sh
#   or with custom options:
#   curl -fsSL https://secretharbor.dev/install.sh | sh -s -- --version 0.4.0

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

# 1. Detect Operating System and Architecture
detect_platform() {
    OS="$(uname -s)"
    case "$OS" in
        Darwin) OS="darwin" ;;
        Linux)  OS="linux" ;;
        *)
            error "Unsupported operating system: $OS. Please install manually from https://secretharbor.dev/releases"
            ;;
    esac

    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        arm64|aarch64)  ARCH="arm64" ;;
        *)
            error "Unsupported CPU architecture: $ARCH. Please install manually from https://secretharbor.dev/releases"
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
}

# 2. Parse Arguments
TARGET_VERSION=""
DRY_RUN=0
NON_INTERACTIVE=0

if [ "${CI:-0}" = "1" ] || [ ! -t 0 ]; then
    NON_INTERACTIVE=1
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --version|-v)
            TARGET_VERSION="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -y|--yes)
            NON_INTERACTIVE=1
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

mkdir -p "$INSTALL_DIR" || error "Failed to create installation directory: $INSTALL_DIR"

# 4. Fetch Release Metadata & Determine Version
BASE_URL="${SECRETHARBOR_UPDATE_URL:-https://releases.secretharbor.dev}"
MANIFEST_URL="${BASE_URL}/manifest.json"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'shb-install')"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if command -v curl >/dev/null 2>&1; then
    FETCH_CMD="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
    FETCH_CMD="wget -qO-"
else
    error "Neither curl nor wget was found on your system. Please install curl or wget."
fi

VERSION="$TARGET_VERSION"
MANIFEST_FILE="$TMP_DIR/manifest.json"

if [ -z "$VERSION" ]; then
    info "Fetching release metadata from ${MANIFEST_URL}..."
    if $FETCH_CMD "$MANIFEST_URL" > "$MANIFEST_FILE" 2>/dev/null; then
        VERSION="$(grep -o '"version": "[^"]*"' "$MANIFEST_FILE" 2>/dev/null | head -n 1 | cut -d'"' -f4 || true)"
    fi
fi

# Fallback default version if manifest unreachable and version unspecified
if [ -z "$VERSION" ]; then
    VERSION="0.4.0"
fi
# Strip optional leading 'v'
VERSION="$(echo "$VERSION" | sed 's/^v//')"

# 5. Determine GoReleaser Artifact Name and URLs
ARTIFACT_NAME="secretharbor_${VERSION}_${OS}_${ARCH}.tar.gz"
PRIMARY_URL="${BASE_URL}/v${VERSION}/${ARTIFACT_NAME}"
GH_FALLBACK="https://github.com/secretharbor/secretharbor/releases/download/v${VERSION}/${ARTIFACT_NAME}"
DOWNLOAD_FILE="$TMP_DIR/${ARTIFACT_NAME}"

info "Release artifact: ${ARTIFACT_NAME} (v${VERSION})"

if [ "$DRY_RUN" = "1" ]; then
    info "Dry run requested. Skipping download and execution."
    success "Platform check passed: ${PLATFORM} (version ${VERSION})"
    exit 0
fi

# Checksum verification helper
verify_checksum() {
    FILE="$1"
    EXPECTED_SHA="$2"

    if [ -z "$EXPECTED_SHA" ]; then
        error "No cryptographic checksum provided for verification. Aborting installation."
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_SHA="$(sha256sum "$FILE" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL_SHA="$(shasum -a 256 "$FILE" | awk '{print $1}')"
    elif command -v openssl >/dev/null 2>&1; then
        ACTUAL_SHA="$(openssl dgst -sha256 "$FILE" | awk '{print $NF}')"
    else
        error "No SHA-256 utility (sha256sum, shasum, or openssl) found. Cannot verify binary integrity."
    fi

    if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
        error "Cryptographic checksum mismatch! Expected: ${EXPECTED_SHA}, Got: ${ACTUAL_SHA}"
    fi

    success "Cryptographic checksum verified (SHA-256: ${ACTUAL_SHA})"
}

# 6. Fetch Checksum and Download Artifact
CHECKSUMS_FILE="$TMP_DIR/checksums.txt"
CHECKSUMS_URL="${BASE_URL}/v${VERSION}/checksums.txt"
GH_CHECKSUMS="https://github.com/secretharbor/secretharbor/releases/download/v${VERSION}/checksums.txt"

info "Downloading checksums..."
if ! $FETCH_CMD "$CHECKSUMS_URL" > "$CHECKSUMS_FILE" 2>/dev/null; then
    $FETCH_CMD "$GH_CHECKSUMS" > "$CHECKSUMS_FILE" 2>/dev/null || true
fi

EXPECTED_SHA=""
if [ -s "$CHECKSUMS_FILE" ]; then
    EXPECTED_SHA="$(grep "${ARTIFACT_NAME}" "$CHECKSUMS_FILE" | awk '{print $1}' || true)"
fi

if [ -z "$EXPECTED_SHA" ] && [ -s "$MANIFEST_FILE" ]; then
    EXPECTED_SHA="$(grep -A 5 "\"${PLATFORM}\"" "$MANIFEST_FILE" 2>/dev/null | grep '"sha256"' | head -n 1 | cut -d'"' -f4 || true)"
fi

info "Downloading SecretHarbor release for ${PLATFORM}..."
if ! $FETCH_CMD "$PRIMARY_URL" > "$DOWNLOAD_FILE" 2>/dev/null; then
    info "Central endpoint unreachable, falling back to GitHub release asset..."
    if ! $FETCH_CMD "$GH_FALLBACK" > "$DOWNLOAD_FILE" 2>/dev/null; then
        error "Failed to download ${ARTIFACT_NAME} from ${PRIMARY_URL} or ${GH_FALLBACK}"
    fi
fi

# Cryptographically verify the downloaded archive
if [ -n "$EXPECTED_SHA" ]; then
    verify_checksum "$DOWNLOAD_FILE" "$EXPECTED_SHA"
else
    warn "Checksums file unavailable; attempting to verify from manifest..."
    if [ -s "$MANIFEST_FILE" ]; then
        EXPECTED_SHA="$(grep -A 5 "\"${PLATFORM}\"" "$MANIFEST_FILE" 2>/dev/null | grep '"sha256"' | head -n 1 | cut -d'"' -f4 || true)"
    fi
    if [ -n "$EXPECTED_SHA" ]; then
        verify_checksum "$DOWNLOAD_FILE" "$EXPECTED_SHA"
    else
        error "Failed to obtain verified SHA-256 checksum for ${ARTIFACT_NAME}. Installation aborted."
    fi
fi

# 7. Extract and Install Executable Atomically
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

if [ -n "$MAN_DIR" ]; then
    if [ -d "$EXTRACT_DIR/man/man1" ]; then
        cp -f "$EXTRACT_DIR/man/man1/"*.1 "$MAN_DIR/" 2>/dev/null || true
        info "Installed man pages to ${MAN_DIR}"
    elif [ -d "man/man1" ]; then
        cp -f man/man1/*.1 "$MAN_DIR/" 2>/dev/null || true
    fi
fi

# 9. Verification and Post-Install Instructions
success "SecretHarbor installed successfully!"
success "Executable: ${TARGET_SHB}"
success "Alias:      ${TARGET_SECRET_HARBOR}"

# Check if INSTALL_DIR is in PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        warn "$INSTALL_DIR is not currently in your PATH."
        printf "Add it to your profile by running:\n"
        printf "  export PATH=\"%s:\$PATH\"\n\n" "$INSTALL_DIR"
        ;;
esac

# Execute version audit verification
if command -v "$TARGET_SHB" >/dev/null 2>&1; then
    "$TARGET_SHB" version 2>/dev/null || true
fi

printf "\nRun:\n"
printf "  shb init\n"
printf "  shb run claude\n"
