#!/usr/bin/env bash
set -euo pipefail

VERSION="${SING_BOX_VERSION:-v1.12.22}"
ROUNDS="${KELI_TROJAN_WS_ROUNDS:-3}"
INTERVAL_MS="${KELI_TROJAN_WS_INTERVAL_MS:-100}"
CASE="${KELI_TROJAN_WS_CASE:-trojan-ws}"
BASE_PORT="${KELI_TROJAN_WS_BASE_PORT:-19420}"
CORE_BIN="${KELI_CORE_BIN:-}"
SING_BOX_BIN="${SING_BOX_BIN:-}"
SKIP_BUILD=0

usage() {
  cat <<EOF
Usage: $0 [options]

Runs sing-box real-client interop against native keli-core-rs Trojan WebSocket cases on Linux.

Options:
  --version VERSION       sing-box release version (default: ${VERSION})
  --core PATH             keli-core-rs binary path (default: target/release/keli-core-rs)
  --sing-box PATH         sing-box client path; downloaded when omitted
  --rounds N              probe rounds (default: ${ROUNDS})
  --interval-ms N         delay between rounds (default: ${INTERVAL_MS})
  --case NAME             interop case substring (default: ${CASE}; matches plain and TLS WS)
  --base-port PORT        first local high port to use (default: ${BASE_PORT})
  --skip-build            do not run cargo build --release --locked
  -h, --help              show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --core)
      CORE_BIN="$2"
      shift 2
      ;;
    --sing-box)
      SING_BOX_BIN="$2"
      shift 2
      ;;
    --rounds)
      ROUNDS="$2"
      shift 2
      ;;
    --interval-ms)
      INTERVAL_MS="$2"
      shift 2
      ;;
    --case)
      CASE="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${ROUNDS}" == "0" ]]; then
  echo "--rounds must be greater than 0" >&2
  exit 2
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd cargo
need_cmd curl
need_cmd tar

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VERSION_NO_V="${VERSION#v}"
CORE_BIN="${CORE_BIN:-${ROOT_DIR}/target/release/keli-core-rs}"
SING_DIR="${ROOT_DIR}/tools/sing-box/sing-box-${VERSION_NO_V}-linux-amd64"
SING_BOX_BIN="${SING_BOX_BIN:-${SING_DIR}/sing-box}"

if [[ ! -x "${SING_BOX_BIN}" ]]; then
  archive="sing-box-${VERSION_NO_V}-linux-amd64.tar.gz"
  url="https://github.com/SagerNet/sing-box/releases/download/${VERSION}/${archive}"
  mkdir -p "$(dirname "${SING_DIR}")"
  echo "downloading sing-box ${VERSION}"
  curl -fsSL "${url}" -o "/tmp/${archive}"
  tar -xzf "/tmp/${archive}" -C "$(dirname "${SING_DIR}")"
  chmod +x "${SING_BOX_BIN}"
fi
"${SING_BOX_BIN}" version | sed -n '1,5p'

if [[ "${SKIP_BUILD}" != "1" ]]; then
  cargo build --release --locked
fi

cargo run --locked --release --example interop_matrix -- \
  --core "${CORE_BIN}" \
  --sing-box "${SING_BOX_BIN}" \
  --client sing-box \
  --only "${CASE}" \
  --probe-rounds "${ROUNDS}" \
  --probe-interval-ms "${INTERVAL_MS}" \
  --base-port "${BASE_PORT}" \
  --keep
