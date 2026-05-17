#!/usr/bin/env bash
set -euo pipefail

VERSION="${NAIVEPROXY_VERSION:-v148.0.7778.96-5}"
ROUNDS="${KELI_NAIVE_SOAK_ROUNDS:-1800}"
INTERVAL_MS="${KELI_NAIVE_SOAK_INTERVAL_MS:-1000}"
RESTART_EVERY="${KELI_NAIVE_RESTART_EVERY_ROUNDS:-0}"
SERVER_NAME="${KELI_NAIVE_SOAK_SERVER_NAME:-naive.local.test}"
CASE="${KELI_NAIVE_SOAK_CASE:-naive}"
NETEM_IFACE="${KELI_NAIVE_NETEM_IFACE:-lo}"
NETEM_ARGS="${KELI_NAIVE_NETEM_ARGS:-}"
CORE_BIN="${KELI_CORE_BIN:-}"
NAIVE_BIN="${NAIVE_BIN:-}"
NET_LOG="${KELI_NAIVE_NET_LOG:-0}"
IGNORE_SPKI_LIST="${KELI_NAIVE_IGNORE_SPKI_LIST:-}"
MAX_RETRY_ATTEMPTS="${KELI_NAIVE_MAX_RETRY_ATTEMPTS:-}"
MAX_P99_MS="${KELI_NAIVE_MAX_P99_MS:-}"
SKIP_BUILD=0

usage() {
  cat <<EOF
Usage: $0 [options]

Runs official NaiveProxy against native keli-core-rs Naive cases on Linux.

Options:
  --version VERSION              NaiveProxy release version (default: ${VERSION})
  --core PATH                    keli-core-rs binary path (default: target/release/keli-core-rs)
  --naive PATH                   official naive binary path; downloaded when omitted
  --rounds N                     probe rounds (default: ${ROUNDS})
  --interval-ms N                delay between rounds (default: ${INTERVAL_MS})
  --restart-every-rounds N       restart official NaiveProxy every N rounds (default: disabled)
  --server-name NAME             certificate SAN / SNI name (default: ${SERVER_NAME})
  --case NAME                    interop case substring (default: ${CASE}; use naive-h3-quic for QUIC only)
  --netem "ARGS"                 optional tc netem args, for example: "delay 80ms 20ms loss 1%"
  --netem-iface IFACE            interface for netem (default: ${NETEM_IFACE})
  --net-log                      capture official NaiveProxy Chromium NetLog artifacts
  --ignore-spki-list VALUE       pass Chromium SPKI allowlist; auto-generated for the test cert when omitted
  --max-retry-attempts N         fail the soak when total probe retries exceed N
  --max-p99-ms N                 fail the soak when probe p99 latency exceeds N ms
  --skip-build                   do not run cargo build --release --locked
  -h, --help                     show this help

Notes:
  - The script installs a short-lived local CA root into /usr/local/share/ca-certificates
    and removes it on exit.
  - When --netem is set, the script applies tc qdisc to the selected interface and
    removes it on exit.
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
    --naive)
      NAIVE_BIN="$2"
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
    --restart-every-rounds)
      RESTART_EVERY="$2"
      shift 2
      ;;
    --server-name)
      SERVER_NAME="$2"
      shift 2
      ;;
    --case)
      CASE="$2"
      shift 2
      ;;
    --netem)
      NETEM_ARGS="$2"
      shift 2
      ;;
    --netem-iface)
      NETEM_IFACE="$2"
      shift 2
      ;;
    --net-log)
      NET_LOG=1
      shift
      ;;
    --ignore-spki-list)
      IGNORE_SPKI_LIST="$2"
      shift 2
      ;;
    --max-retry-attempts)
      MAX_RETRY_ATTEMPTS="$2"
      shift 2
      ;;
    --max-p99-ms)
      MAX_P99_MS="$2"
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
if [[ "${RESTART_EVERY}" == "0" ]]; then
  RESTART_EVERY=""
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

CORE_BIN="${CORE_BIN:-${ROOT_DIR}/target/release/keli-core-rs}"
NAIVE_DIR="${ROOT_DIR}/tools/naiveproxy/naiveproxy-${VERSION}-linux-x64"
NAIVE_BIN="${NAIVE_BIN:-${NAIVE_DIR}/naive}"
CERT_DIR="${ROOT_DIR}/runtime/interop-certs"
CA_PATH="${CERT_DIR}/naive-${SERVER_NAME}-ca.crt"
CA_KEY_PATH="${CERT_DIR}/naive-${SERVER_NAME}-ca.key"
CERT_PATH="${CERT_DIR}/naive-${SERVER_NAME}.crt"
KEY_PATH="${CERT_DIR}/naive-${SERVER_NAME}.key"
CSR_PATH="${CERT_DIR}/naive-${SERVER_NAME}.csr"
CA_OPENSSL_CNF="${CERT_DIR}/naive-${SERVER_NAME}.ca.openssl.cnf"
OPENSSL_CNF="${CERT_DIR}/naive-${SERVER_NAME}.openssl.cnf"
SYSTEM_CERT="/usr/local/share/ca-certificates/keli-naive-interop.crt"
CERT_INSTALLED=0
NETEM_INSTALLED=0

cleanup() {
  if [[ "${NETEM_INSTALLED}" == "1" ]]; then
    sudo tc qdisc del dev "${NETEM_IFACE}" root >/dev/null 2>&1 || true
  fi
  if [[ "${CERT_INSTALLED}" == "1" ]]; then
    sudo rm -f "${SYSTEM_CERT}" >/dev/null 2>&1 || true
    sudo update-ca-certificates >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd cargo
need_cmd curl
need_cmd tar
need_cmd openssl
need_cmd sudo

if [[ ! -x "${NAIVE_BIN}" ]]; then
  archive="naiveproxy-${VERSION}-linux-x64.tar.xz"
  url="https://github.com/klzgrad/naiveproxy/releases/download/${VERSION}/${archive}"
  mkdir -p "${NAIVE_DIR}"
  echo "downloading official NaiveProxy ${VERSION}"
  curl -fsSL "${url}" -o "/tmp/${archive}"
  tar -xJf "/tmp/${archive}" -C "${NAIVE_DIR}" --strip-components=1
  chmod +x "${NAIVE_BIN}"
fi
"${NAIVE_BIN}" --version

mkdir -p "${CERT_DIR}"
cat > "${CA_OPENSSL_CNF}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = Keli Naive Interop Local CA

[v3_ca]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

cat > "${OPENSSL_CNF}" <<EOF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = ${SERVER_NAME}

[v3_req]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVER_NAME}
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${CA_KEY_PATH}" \
  -out "${CA_PATH}" \
  -days 1 \
  -config "${CA_OPENSSL_CNF}" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
  -keyout "${KEY_PATH}" \
  -out "${CSR_PATH}" \
  -days 1 \
  -config "${OPENSSL_CNF}" >/dev/null 2>&1

openssl x509 -req \
  -in "${CSR_PATH}" \
  -CA "${CA_PATH}" \
  -CAkey "${CA_KEY_PATH}" \
  -CAcreateserial \
  -out "${CERT_PATH}" \
  -days 1 \
  -extensions v3_req \
  -extfile "${OPENSSL_CNF}" >/dev/null 2>&1

sudo cp "${CA_PATH}" "${SYSTEM_CERT}"
sudo update-ca-certificates >/dev/null
CERT_INSTALLED=1

if [[ -z "${IGNORE_SPKI_LIST}" ]]; then
  IGNORE_SPKI_LIST="$(
    openssl x509 -in "${CERT_PATH}" -pubkey -noout \
      | openssl pkey -pubin -outform DER \
      | openssl dgst -sha256 -binary \
      | openssl base64 -A
  )"
fi

if [[ -n "${NETEM_ARGS}" ]]; then
  need_cmd tc
  sudo tc qdisc del dev "${NETEM_IFACE}" root >/dev/null 2>&1 || true
  sudo tc qdisc add dev "${NETEM_IFACE}" root netem ${NETEM_ARGS}
  NETEM_INSTALLED=1
  echo "netem enabled on ${NETEM_IFACE}: ${NETEM_ARGS}"
fi

if [[ "${SKIP_BUILD}" != "1" ]]; then
  cargo build --release --locked
fi

args=(
  --core "${CORE_BIN}"
  --client naive
  --naive "${NAIVE_BIN}"
  --only "${CASE}"
  --tls-cert "${CERT_PATH}"
  --tls-key "${KEY_PATH}"
  --naive-server-name "${SERVER_NAME}"
  --probe-rounds "${ROUNDS}"
  --probe-interval-ms "${INTERVAL_MS}"
  --keep
)
if [[ -n "${RESTART_EVERY}" ]]; then
  args+=(--naive-restart-every-rounds "${RESTART_EVERY}")
fi
if [[ "${NET_LOG}" == "1" || "${NET_LOG}" == "true" || "${NET_LOG}" == "TRUE" ]]; then
  args+=(--naive-net-log)
fi
if [[ -n "${IGNORE_SPKI_LIST}" ]]; then
  args+=(--naive-ignore-spki-list "${IGNORE_SPKI_LIST}")
fi
if [[ -n "${MAX_RETRY_ATTEMPTS}" ]]; then
  args+=(--max-retry-attempts "${MAX_RETRY_ATTEMPTS}")
fi
if [[ -n "${MAX_P99_MS}" ]]; then
  args+=(--max-p99-ms "${MAX_P99_MS}")
fi

cargo run --locked --release --example interop_matrix -- "${args[@]}"
