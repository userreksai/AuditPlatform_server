#!/usr/bin/env bash
# Native Linux/systemd installation. Builds both repositories before touching the service.
set -Eeuo pipefail
umask 027
trap 'printf "Installation failed at line %s; existing config/database are retained.\n" "$LINENO" >&2' ERR

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WEB_SOURCE="${WEB_SOURCE:-}"
LISTEN="${LISTEN:-0.0.0.0:8080}"
START=1
INSTALL_DEPS=1
while (($#)); do
  case "$1" in
    --web-source) WEB_SOURCE="${2:?Missing web source}"; shift 2 ;;
    --listen) LISTEN="${2:?Missing listen address}"; shift 2 ;;
    --no-start) START=0; shift ;;
    --no-deps) INSTALL_DEPS=0; shift ;;
    -h|--help)
      printf '%s\n' 'sudo bash install.sh [--web-source ../AuditPlatform_web] [--listen 0.0.0.0:8080] [--no-start] [--no-deps]' 'Installs to /opt/aws-audit; preserves /etc/aws-audit/config.yaml and /var/lib/aws-audit.'
      exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ $(uname -s) == Linux ]] || { echo 'Linux is required.' >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo 'Run using sudo bash install.sh.' >&2; exit 1; }
[[ $LISTEN =~ ^[][a-zA-Z0-9.:-]+$ ]] || { echo 'Invalid listen address.' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd is required.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'systemd must be running (use a Linux VM/server).' >&2; exit 1; }

if ((INSTALL_DEPS)); then
  if command -v apt-get >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git tar gzip xz-utils python3
  elif command -v dnf >/dev/null; then
    dnf install -y ca-certificates curl git tar gzip xz python3 shadow-utils
  elif command -v yum >/dev/null; then
    yum install -y ca-certificates curl git tar gzip xz python3 shadow-utils
  else
    echo 'Unsupported package manager. Install curl/git/tar/gzip/xz/python3 manually, then use --no-deps.' >&2
    exit 1
  fi
fi
for dependency in curl git tar python3 sha256sum install; do
  command -v "$dependency" >/dev/null || { echo "Missing dependency: $dependency" >&2; exit 1; }
done

STAGE="$(mktemp -d /tmp/aws-audit-build.XXXXXXXX)"
cleanup() { [[ $STAGE == /tmp/aws-audit-build.* && -d $STAGE ]] && rm -rf -- "$STAGE"; }
trap cleanup EXIT
case "$(uname -m)" in
  x86_64) GO_ARCH=amd64; NODE_ARCH=x64 ;;
  aarch64|arm64) GO_ARCH=arm64; NODE_ARCH=arm64 ;;
  *) echo 'Only Linux amd64 and arm64 are supported.' >&2; exit 1 ;;
esac
download() { curl --fail --location --retry 3 --connect-timeout 20 --proto '=https' --tlsv1.2 "$1" -o "$2"; }

# Official release metadata and SHA256 verification; no global SDK installation.
download 'https://go.dev/dl/?mode=json' "$STAGE/go-releases.json"
python3 - "$STAGE/go-releases.json" "$GO_ARCH" > "$STAGE/go-release" <<'PY'
import json, sys
releases=json.load(open(sys.argv[1]))
release=next(r for r in releases if r['stable'])
f=next(f for f in release['files'] if f['os']=='linux' and f['arch']==sys.argv[2] and f['kind']=='archive')
print(f['filename'], f['sha256'])
PY
read -r GO_FILE GO_SHA < "$STAGE/go-release"
download "https://go.dev/dl/$GO_FILE" "$STAGE/go.tar.gz"
printf '%s  %s\n' "$GO_SHA" "$STAGE/go.tar.gz" | sha256sum --check --status
tar -xzf "$STAGE/go.tar.gz" -C "$STAGE"

download 'https://nodejs.org/dist/index.json' "$STAGE/node-releases.json"
NODE_VERSION="$(python3 - "$STAGE/node-releases.json" "$NODE_ARCH" <<'PY'
import json, sys
releases=json.load(open(sys.argv[1]))
print(next(r['version'] for r in releases if r['lts'] and 'linux-'+sys.argv[2] in r['files']))
PY
)"
NODE_FILE="node-$NODE_VERSION-linux-$NODE_ARCH.tar.xz"
download "https://nodejs.org/dist/$NODE_VERSION/SHASUMS256.txt" "$STAGE/node-shasums"
download "https://nodejs.org/dist/$NODE_VERSION/$NODE_FILE" "$STAGE/$NODE_FILE"
NODE_SHA="$(awk -v file="$NODE_FILE" '$2==file {print $1}' "$STAGE/node-shasums")"
[[ $NODE_SHA =~ ^[0-9a-f]{64}$ ]] || { echo 'Node release checksum missing.' >&2; exit 1; }
printf '%s  %s\n' "$NODE_SHA" "$STAGE/$NODE_FILE" | sha256sum --check --status
mkdir "$STAGE/node"
tar -xJf "$STAGE/$NODE_FILE" -C "$STAGE/node" --strip-components=1
export PATH="$STAGE/node/bin:$STAGE/go/bin:$PATH"
export CI=true
export GOPATH="$STAGE/go-cache" GOCACHE="$STAGE/build-cache"

if [[ -z $WEB_SOURCE ]]; then
  if [[ -f $SOURCE_DIR/../AuditPlatform_web/package.json ]]; then
    WEB_SOURCE="$SOURCE_DIR/../AuditPlatform_web"
  else
    git clone --depth 1 https://github.com/userreksai/AuditPlatform_web.git "$STAGE/web-source"
    WEB_SOURCE="$STAGE/web-source"
  fi
fi
WEB_SOURCE="$(cd -- "$WEB_SOURCE" && pwd)"
[[ -f $WEB_SOURCE/package.json && -f $WEB_SOURCE/pnpm-lock.yaml ]] || { echo 'Vue source and pnpm-lock.yaml are required.' >&2; exit 1; }
PNPM_SPEC="$(python3 - "$WEB_SOURCE/package.json" <<'PY'
import json, re, sys
spec=json.load(open(sys.argv[1])).get('packageManager', '')
if not re.fullmatch(r'pnpm@\d+\.\d+\.\d+', spec): raise SystemExit('Expected pinned pnpm packageManager')
print(spec)
PY
)"
npm install --prefix "$STAGE/package-manager" --no-audit --no-fund "$PNPM_SPEC"
PNPM="$STAGE/package-manager/node_modules/.bin/pnpm"
(
  cd "$WEB_SOURCE"
  "$PNPM" install --frozen-lockfile
  "$PNPM" run build
)
(
  cd "$SOURCE_DIR"
  go mod download
  go test ./...
  CGO_ENABLED=0 go build -trimpath -o "$STAGE/audit-server" ./cmd/audit-server
)
"$STAGE/audit-server" -version
[[ -f $WEB_SOURCE/dist/index.html ]] || { echo 'Frontend build output missing.' >&2; exit 1; }

getent group aws-audit >/dev/null || groupadd --system aws-audit
id aws-audit >/dev/null 2>&1 || useradd --system --gid aws-audit --home-dir /var/lib/aws-audit --shell /usr/sbin/nologin aws-audit
install -d -m 0755 /opt/aws-audit /opt/aws-audit/releases
install -d -m 0750 -o root -g aws-audit /etc/aws-audit
install -d -m 0750 -o aws-audit -g aws-audit /var/lib/aws-audit
RELEASE="/opt/aws-audit/releases/$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 0755 "$RELEASE/web"
install -m 0755 "$STAGE/audit-server" "$RELEASE/audit-server"
cp -R "$WEB_SOURCE/dist/." "$RELEASE/web/"
chmod -R a+rX "$RELEASE/web"
if [[ ! -f /etc/aws-audit/config.yaml ]]; then
  cat > /etc/aws-audit/config.yaml <<YAML
server:
  address: "$LISTEN"
  web_directory: "/opt/aws-audit/current/web"
  secure_cookie: false
  session_hours: 12
database:
  path: "/var/lib/aws-audit/audit.db"
auth:
  username: "auditroot"
  password: "a181818."
sync:
  time: "09:00"
  timezone: "Asia/Shanghai"
  timeout_minutes: 30
accounts: []
YAML
fi
chown root:aws-audit /etc/aws-audit/config.yaml
chmod 0640 /etc/aws-audit/config.yaml
"$RELEASE/audit-server" -config /etc/aws-audit/config.yaml -check-config
PREVIOUS="$(readlink /opt/aws-audit/current || true)"
ln -s "$RELEASE" "/opt/aws-audit/current.new.$$"
mv -Tf "/opt/aws-audit/current.new.$$" /opt/aws-audit/current
install -m 0644 "$SOURCE_DIR/deploy/aws-audit.service" /etc/systemd/system/aws-audit.service
systemctl daemon-reload
systemctl enable aws-audit.service
if ((START)); then
  systemctl restart aws-audit.service
  sleep 2
  if ! systemctl is-active --quiet aws-audit.service; then
    journalctl -u aws-audit.service -n 30 --no-pager
    if [[ -n $PREVIOUS && -d $PREVIOUS ]]; then
      ln -s "$PREVIOUS" "/opt/aws-audit/current.rollback.$$"
      mv -Tf "/opt/aws-audit/current.rollback.$$" /opt/aws-audit/current
      systemctl restart aws-audit.service || true
      echo 'Restored the previous application release; configuration/database retained.' >&2
    fi
    exit 1
  fi
fi
printf '\nInstalled successfully.\nConfig: /etc/aws-audit/config.yaml\nDefault login: auditroot / a181818.\nSchedule: daily 09:00 Asia/Shanghai\nAdd AWS keys to config, then: sudo systemctl restart aws-audit\nLogs: sudo journalctl -u aws-audit -f\n'
