#!/usr/bin/env bash
set -euo pipefail

VERSION="${MIERU_VERSION:-v3.32.0}"
ROUNDS="${KELI_MIERU_SOAK_ROUNDS:-3}"
INTERVAL_MS="${KELI_MIERU_SOAK_INTERVAL_MS:-100}"
CASE="${KELI_MIERU_SOAK_CASE:-mieru-tcp-underlay}"
BASE_PORT="${KELI_MIERU_BASE_PORT:-19380}"
CORE_BIN="${KELI_CORE_BIN:-}"
MIERU_BIN="${MIERU_BIN:-}"
SKIP_BUILD=0
KEEP=0

usage() {
  cat <<EOF
Usage: $0 [options]

Runs official Mieru client interop against native keli-core-rs Mieru TCP underlay on Linux.

Options:
  --version VERSION       official Mieru release version (default: ${VERSION})
  --core PATH             keli-core-rs binary path (default: target/release/keli-core-rs)
  --mieru PATH            official mieru client path; downloaded when omitted
  --rounds N              successful TCP probe rounds (default: ${ROUNDS})
  --interval-ms N         delay between rounds (default: ${INTERVAL_MS})
  --case NAME             evidence case label (default: ${CASE})
  --base-port PORT        first local high port to use (default: ${BASE_PORT})
  --skip-build            do not run cargo build --release --locked
  --keep                  keep runtime logs/configs after exit
  -h, --help              show this help

Evidence covered:
  - official client auth success and auth failure
  - TCP CONNECT relay through official client SOCKS5
  - SOCKS UDP ASSOCIATE through TCP underlay
  - multiplexed concurrent TCP sessions
  - traffic accounting through the native control socket
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
    --mieru)
      MIERU_BIN="$2"
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
    --keep)
      KEEP=1
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
need_cmd dpkg-deb
need_cmd python3
need_cmd ss

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VERSION_NO_V="${VERSION#v}"
CORE_BIN="${CORE_BIN:-${ROOT_DIR}/target/release/keli-core-rs}"
WORK_DIR="${ROOT_DIR}/runtime/mieru-official-${CASE}"
TOOLS_DIR="${ROOT_DIR}/tools/mieru/${VERSION}"
MIERU_BIN="${MIERU_BIN:-${TOOLS_DIR}/usr/bin/mieru}"

MIERU_PORT="${BASE_PORT}"
HTTP_PORT="$((BASE_PORT + 1))"
SOCKS_PORT="$((BASE_PORT + 2))"
RPC_PORT="$((BASE_PORT + 3))"
CONTROL_PORT="$((BASE_PORT + 4))"
UDP_PORT="$((BASE_PORT + 5))"
BAD_SOCKS_PORT="$((BASE_PORT + 6))"
BAD_RPC_PORT="$((BASE_PORT + 7))"

for port in "${MIERU_PORT}" "${HTTP_PORT}" "${SOCKS_PORT}" "${RPC_PORT}" "${CONTROL_PORT}" "${UDP_PORT}" "${BAD_SOCKS_PORT}" "${BAD_RPC_PORT}"; do
  if ss -H -ltn "sport = :${port}" | grep -q . || ss -H -lun "sport = :${port}" | grep -q .; then
    echo "port ${port} is already in use" >&2
    exit 1
  fi
done

cleanup() {
  kill "${CORE_PID:-0}" "${MIERU_PID:-0}" "${BAD_MIERU_PID:-0}" "${HTTP_PID:-0}" "${UDP_PID:-0}" >/dev/null 2>&1 || true
  if [[ "${KEEP}" != "1" ]]; then
    rm -rf "${WORK_DIR}"
  fi
}
trap cleanup EXIT

if [[ ! -x "${MIERU_BIN}" ]]; then
  mkdir -p "${TOOLS_DIR}"
  archive="mieru_${VERSION_NO_V}_amd64.deb"
  url="https://github.com/enfein/mieru/releases/download/${VERSION}/${archive}"
  echo "downloading official Mieru ${VERSION}"
  curl -fsSL "${url}" -o "${TOOLS_DIR}/${archive}"
  if curl -fsSL "${url}.sha256.txt" -o "${TOOLS_DIR}/${archive}.sha256.txt"; then
    (cd "${TOOLS_DIR}" && sha256sum -c "${archive}.sha256.txt")
  fi
  dpkg-deb -x "${TOOLS_DIR}/${archive}" "${TOOLS_DIR}"
  chmod +x "${MIERU_BIN}"
fi
"${MIERU_BIN}" version

if [[ "${SKIP_BUILD}" != "1" ]]; then
  cargo build --release --locked
fi

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"
printf 'keli mieru official tcp relay\n' > "${WORK_DIR}/probe.txt"

cat > "${WORK_DIR}/core.json" <<JSON
{
  "instance_id": "mieru-official",
  "log_level": "debug",
  "dns": {
    "servers": [],
    "query_strategy": "",
    "block_private_ips": false,
    "private_ip_allowlist": []
  },
  "policy": {
    "handshake_secs": 5,
    "connection_idle_secs": 30,
    "uplink_only_secs": 5,
    "downlink_only_secs": 5,
    "buffer_size_kib": 64,
    "sniffing_cache_millis": 200,
    "connect_timeout_secs": 5
  },
  "inbounds": [
    {
      "tag": "panel|mieru|1",
      "protocol": "mieru",
      "listen": "127.0.0.1",
      "port": ${MIERU_PORT},
      "users": [
        {
          "id": 1,
          "uuid": "keli-mieru-user",
          "password": "keli-mieru-pass",
          "email": null,
          "speed_limit": 0,
          "device_limit": 0
        }
      ],
      "cipher": null,
      "flow": "",
      "padding_scheme": [],
      "transport": {
        "network": "tcp",
        "path": null,
        "host": null,
        "service_name": null,
        "proxy_protocol": false,
        "up_mbps": 0,
        "down_mbps": 0,
        "ignore_client_bandwidth": false,
        "obfs": null,
        "obfs_password": null,
        "congestion_control": "",
        "zero_rtt_handshake": false
      },
      "tls": null,
      "sniffing": {
        "enabled": false,
        "dest_override": []
      },
      "routes": []
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routes": [],
  "stats": {
    "enabled": true,
    "per_user": true
  }
}
JSON

write_mieru_config() {
  local path="$1"
  local password="$2"
  local socks_port="$3"
  local rpc_port="$4"
  cat > "${path}" <<JSON
{
  "profiles": [
    {
      "profileName": "default",
      "user": {
        "name": "keli-mieru-user",
        "password": "${password}"
      },
      "servers": [
        {
          "ipAddress": "127.0.0.1",
          "domainName": "",
          "portBindings": [
            {
              "port": ${MIERU_PORT},
              "protocol": "TCP"
            }
          ]
        }
      ],
      "mtu": 1400,
      "multiplexing": {
        "level": "MULTIPLEXING_HIGH"
      },
      "handshakeMode": "HANDSHAKE_STANDARD"
    }
  ],
  "activeProfile": "default",
  "rpcPort": ${rpc_port},
  "socks5Port": ${socks_port},
  "loggingLevel": "DEBUG",
  "socks5ListenLAN": false
}
JSON
}

write_mieru_config "${WORK_DIR}/client.json" "keli-mieru-pass" "${SOCKS_PORT}" "${RPC_PORT}"
write_mieru_config "${WORK_DIR}/bad-client.json" "wrong-mieru-pass" "${BAD_SOCKS_PORT}" "${BAD_RPC_PORT}"

cat > "${WORK_DIR}/udp_echo.py" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(b"udp:" + data, addr)
PY

cat > "${WORK_DIR}/socks_udp_probe.py" <<'PY'
import ipaddress
import socket
import struct
import sys

socks_port = int(sys.argv[1])
target_port = int(sys.argv[2])
payload = b"keli-mieru-udp"

control = socket.create_connection(("127.0.0.1", socks_port), timeout=5)
control.sendall(b"\x05\x01\x00")
if control.recv(2) != b"\x05\x00":
    raise SystemExit("SOCKS greeting rejected")
control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
reply = control.recv(10)
if len(reply) != 10 or reply[0] != 5 or reply[1] != 0 or reply[3] != 1:
    raise SystemExit(f"SOCKS UDP ASSOCIATE failed: {reply!r}")
relay_host = str(ipaddress.IPv4Address(reply[4:8]))
relay_port = struct.unpack("!H", reply[8:10])[0]

packet = bytearray(b"\x00\x00\x00\x01")
packet += socket.inet_aton("127.0.0.1")
packet += struct.pack("!H", target_port)
packet += payload

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(packet, (relay_host, relay_port))
data, _ = udp.recvfrom(65535)
if len(data) < 10 or data[:4] != b"\x00\x00\x00\x01":
    raise SystemExit(f"invalid SOCKS UDP response: {data!r}")
body = data[10:]
if body != b"udp:" + payload:
    raise SystemExit(f"unexpected UDP response body: {body!r}")
print("PASS mieru official UDP associate over TCP underlay")
PY

cat > "${WORK_DIR}/control.py" <<'PY'
import json
import socket
import sys

port = int(sys.argv[1])
command = json.loads(sys.argv[2])
stream = socket.create_connection(("127.0.0.1", port), timeout=5)
stream.sendall(json.dumps(command).encode() + b"\n")
response = b""
while not response.endswith(b"\n"):
    chunk = stream.recv(65535)
    if not chunk:
        break
    response += chunk
print(response.decode().strip())
PY

wait_for_tcp() {
  local port="$1"
  local label="$2"
  for _ in $(seq 1 80); do
    if ss -H -ltn "sport = :${port}" | grep -q .; then
      return 0
    fi
    sleep 0.25
  done
  echo "timed out waiting for ${label} on port ${port}" >&2
  return 1
}

python3 -m http.server "${HTTP_PORT}" --bind 127.0.0.1 --directory "${WORK_DIR}" >"${WORK_DIR}/http.log" 2>&1 &
HTTP_PID=$!
python3 "${WORK_DIR}/udp_echo.py" "${UDP_PORT}" >"${WORK_DIR}/udp.log" 2>&1 &
UDP_PID=$!
"${CORE_BIN}" run-config "${WORK_DIR}/core.json" --control "127.0.0.1:${CONTROL_PORT}" >"${WORK_DIR}/core.log" 2>&1 &
CORE_PID=$!
MIERU_CONFIG_JSON_FILE="${WORK_DIR}/client.json" "${MIERU_BIN}" run >"${WORK_DIR}/mieru.log" 2>&1 &
MIERU_PID=$!

wait_for_tcp "${HTTP_PORT}" "http echo"
wait_for_tcp "${MIERU_PORT}" "native mieru"
wait_for_tcp "${CONTROL_PORT}" "core control"
wait_for_tcp "${SOCKS_PORT}" "official mieru socks"

expected="$(cat "${WORK_DIR}/probe.txt")"
for round in $(seq 1 "${ROUNDS}"); do
  body="$(curl -fsS --socks5-hostname "127.0.0.1:${SOCKS_PORT}" "http://127.0.0.1:${HTTP_PORT}/probe.txt")"
  if [[ "${body}" != "${expected}" ]]; then
    echo "unexpected TCP probe body: ${body}" >&2
    exit 1
  fi
  if [[ "${ROUNDS}" != "1" ]]; then
    echo "probe round ${round}/${ROUNDS} passed"
  fi
  if [[ "${round}" != "${ROUNDS}" && "${INTERVAL_MS}" != "0" ]]; then
    sleep "$(awk "BEGIN { printf \"%.3f\", ${INTERVAL_MS}/1000 }")"
  fi
done

python3 "${WORK_DIR}/socks_udp_probe.py" "${SOCKS_PORT}" "${UDP_PORT}"

pids=()
for i in $(seq 1 5); do
  curl -fsS --socks5-hostname "127.0.0.1:${SOCKS_PORT}" "http://127.0.0.1:${HTTP_PORT}/probe.txt" -o "${WORK_DIR}/concurrent-${i}.txt" &
  pids+=("$!")
done
for pid in "${pids[@]}"; do
  wait "${pid}"
done
for file in "${WORK_DIR}"/concurrent-*.txt; do
  if [[ "$(cat "${file}")" != "${expected}" ]]; then
    echo "unexpected multiplexed TCP body in ${file}" >&2
    exit 1
  fi
done
echo "PASS mieru official multiplexed TCP sessions"

traffic="$(
  python3 "${WORK_DIR}/control.py" "${CONTROL_PORT}" '{"type":"drain_traffic","minimum_bytes":1}'
)"
echo "${traffic}" > "${WORK_DIR}/traffic.json"
python3 - "${WORK_DIR}/traffic.json" <<'PY'
import json
import sys

response = json.load(open(sys.argv[1], encoding="utf-8"))
records = response.get("records", [])
matching = [
    record for record in records
    if record.get("node_tag") == "panel|mieru|1"
    and record.get("user_id") == 1
    and record.get("upload", 0) > 0
    and record.get("download", 0) > 0
]
if not matching:
    raise SystemExit(f"missing per-user traffic accounting: {records!r}")
print("PASS mieru official traffic accounting")
PY

MIERU_CONFIG_JSON_FILE="${WORK_DIR}/bad-client.json" "${MIERU_BIN}" run >"${WORK_DIR}/bad-mieru.log" 2>&1 &
BAD_MIERU_PID=$!
wait_for_tcp "${BAD_SOCKS_PORT}" "bad official mieru socks"
if curl -fsS --connect-timeout 3 --max-time 8 --socks5-hostname "127.0.0.1:${BAD_SOCKS_PORT}" "http://127.0.0.1:${HTTP_PORT}/probe.txt" -o "${WORK_DIR}/bad-auth.txt" 2>"${WORK_DIR}/bad-auth-curl.log"; then
  echo "bad Mieru password unexpectedly relayed traffic" >&2
  exit 1
fi
echo "PASS mieru official auth failure rejects relay"

delete_response="$(
  python3 "${WORK_DIR}/control.py" "${CONTROL_PORT}" '{"type":"apply_user_delta","node_tag":"panel|mieru|1","delta":{"deleted":["keli-mieru-user"]}}'
)"
echo "${delete_response}" > "${WORK_DIR}/delete-user.json"
if curl -fsS --connect-timeout 3 --max-time 8 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" "http://127.0.0.1:${HTTP_PORT}/probe.txt" -o "${WORK_DIR}/after-delete.txt" 2>"${WORK_DIR}/after-delete-curl.log"; then
  echo "deleted Mieru user unexpectedly relayed a new request" >&2
  exit 1
fi
echo "PASS mieru official user delta delete rejects new relay"

echo "PASS mieru official remote interop case=${CASE} rounds=${ROUNDS} version=${VERSION}"
