#!/bin/sh
set -eu

REPO_URL="${REFRACT_REPO_URL:-https://github.com/T-Matrix/Refract.git}"
BRANCH="${REFRACT_BRANCH:-main}"
INSTALL_DIR="${REFRACT_INSTALL_DIR:-/opt/refract}"
COMPOSE_VERSION="${REFRACT_COMPOSE_VERSION:-v5.4.0}"
RELEASE_BASE_URL="${REFRACT_RELEASE_BASE_URL:-https://github.com/T-Matrix/Refract/releases/latest/download}"

domain="${REFRACT_DOMAIN:-}"
upstream="${REFRACT_UPSTREAM:-}"
allowed_upstreams="${REFRACT_ALLOWED_UPSTREAMS:-}"
admin_user="${REFRACT_ADMIN_USER:-admin}"
public_proxy="${REFRACT_PUBLIC_PROXY:-false}"
allow_private="${REFRACT_ALLOW_PRIVATE_TARGETS:-false}"
assume_yes=0
inferred_public_proxy=0

usage() {
    cat <<'EOF'
Refract 一键部署脚本

用法：
  install.sh [选项]

选项：
  --domain DOMAIN          已解析到 VPS 的域名
  --upstream URL           默认上游，例如 https://emby.example.com；交互安装可留空
  --allow-hosts LIST       可直接访问的初始上游，逗号分隔
  --admin-user USER        初始管理员用户名，默认 admin
  --public-proxy           允许代理任意公网 HTTP/HTTPS 目标
  --allow-private          允许访问内网目标（高风险）
  --install-dir DIR        安装目录，默认 /opt/refract
  --yes                    跳过确认，适合自动化部署
  -h, --help               显示帮助

环境变量：
  REFRACT_REPO_URL、REFRACT_BRANCH、REFRACT_INSTALL_DIR、REFRACT_COMPOSE_VERSION
  REFRACT_RELEASE_BASE_URL
  REFRACT_DOMAIN、REFRACT_UPSTREAM、REFRACT_ALLOWED_UPSTREAMS
  REFRACT_ADMIN_USER、REFRACT_PUBLIC_PROXY、REFRACT_ALLOW_PRIVATE_TARGETS

重复运行会拉取最新源码并重建容器，已有 .env 和数据卷会保留。
EOF
}

say() {
    printf '\n[Refract] %s\n' "$*"
}

warn() {
    printf '\n[警告] %s\n' "$*" >&2
}

fail() {
    printf '\n[错误] %s\n' "$*" >&2
    exit 1
}

ask() {
    prompt="$1"
    default_value="${2:-}"
    if [ -n "$default_value" ]; then
        printf '%s [%s]: ' "$prompt" "$default_value" >&2
    else
        printf '%s: ' "$prompt" >&2
    fi
    answer=""
    if [ -c /dev/tty ]; then
        IFS= read -r answer </dev/tty || answer=""
    fi
    if [ -n "$answer" ]; then
        printf '%s' "$answer"
    else
        printf '%s' "$default_value"
    fi
}

confirm() {
    prompt="$1"
    default_value="${2:-n}"
    answer="$(ask "$prompt (y/n)" "$default_value")"
    case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

is_true() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

has_interactive_terminal() {
    [ -t 1 ] && [ -c /dev/tty ]
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --domain)
            [ "$#" -ge 2 ] || fail "--domain 缺少值"
            domain="$2"
            shift 2
            ;;
        --upstream)
            [ "$#" -ge 2 ] || fail "--upstream 缺少值"
            upstream="$2"
            shift 2
            ;;
        --allow-hosts)
            [ "$#" -ge 2 ] || fail "--allow-hosts 缺少值"
            allowed_upstreams="$2"
            shift 2
            ;;
        --admin-user)
            [ "$#" -ge 2 ] || fail "--admin-user 缺少值"
            admin_user="$2"
            shift 2
            ;;
        --public-proxy)
            public_proxy=true
            shift
            ;;
        --allow-private)
            allow_private=true
            shift
            ;;
        --install-dir)
            [ "$#" -ge 2 ] || fail "--install-dir 缺少值"
            INSTALL_DIR="$2"
            shift 2
            ;;
        --yes)
            assume_yes=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "未知选项：$1"
            ;;
    esac
done

[ "$(uname -s)" = "Linux" ] || fail "一键脚本只支持 Linux VPS"
[ "$(id -u)" -eq 0 ] || fail "请使用 root 运行，或在命令前加 sudo"

install_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl git openssl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates curl git openssl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y ca-certificates curl git openssl
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache ca-certificates curl git openssl
    else
        fail "未找到受支持的软件包管理器（apt、dnf、yum 或 apk）"
    fi
}

install_docker() {
    say "安装 Docker Engine 与 Compose 插件"
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache docker docker-cli-compose
        return
    fi
    installer="$(mktemp)"
    curl -fsSL https://get.docker.com -o "$installer"
    sh "$installer"
    rm -f "$installer"
}

install_compose_plugin() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) compose_arch="x86_64" ;;
        aarch64|arm64) compose_arch="aarch64" ;;
        *) fail "暂不支持当前 CPU 架构的 Compose 自动安装：$arch" ;;
    esac

    asset="docker-compose-linux-$compose_arch"
    base_url="https://github.com/docker/compose/releases/download/$COMPOSE_VERSION"
    plugin_tmp="$(mktemp)"
    checksum_tmp="$(mktemp)"

    say "安装 Docker Compose $COMPOSE_VERSION"
    curl -fsSL "$base_url/$asset" -o "$plugin_tmp"
    curl -fsSL "$base_url/$asset.sha256" -o "$checksum_tmp"
    expected="$(awk '{print $1}' "$checksum_tmp")"
    actual="$(openssl dgst -sha256 "$plugin_tmp" | awk '{print $NF}')"
    if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
        fail "Docker Compose 校验失败"
    fi

    mkdir -p /usr/local/lib/docker/cli-plugins
    install -m 0755 "$plugin_tmp" /usr/local/lib/docker/cli-plugins/docker-compose
    rm -f "$plugin_tmp" "$checksum_tmp"
}

random_hex() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

valid_domain() {
    value="$1"
    [ "${#value}" -le 253 ] || return 1
    printf '%s' "$value" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' || return 1
    case "$value" in
        *.*) return 0 ;;
        *) return 1 ;;
    esac
}

valid_upstream() {
    printf '%s' "$1" | grep -Eq '^https?://[^/?#[:space:]]+/?$'
}

valid_host_list() {
    [ -z "$1" ] || printf '%s' "$1" | grep -Eq '^[A-Za-z0-9.*,:_-]+$'
}

valid_admin_user() {
    printf '%s' "$1" | grep -Eq '^[A-Za-z0-9_.@-]{1,64}$'
}

legacy_systemd_install() {
    [ "$INSTALL_DIR" = "/opt/refract" ] &&
        [ ! -f "$INSTALL_DIR/.env" ] &&
        [ -x /opt/vps-url-gateway/vps-url-gateway ] &&
        [ -f /etc/vps-url-gateway.env ] &&
        [ -f /etc/systemd/system/vps-url-gateway.service ] &&
        command -v systemctl >/dev/null 2>&1
}

update_legacy_systemd() {
    legacy_dir=/opt/vps-url-gateway
    legacy_binary="$legacy_dir/vps-url-gateway"
    legacy_arch="$(uname -m)"
    case "$legacy_arch" in
        x86_64|amd64) legacy_asset=refract-linux-amd64 ;;
        aarch64|arm64) legacy_asset=refract-linux-arm64 ;;
        *) fail "暂不支持当前 CPU 架构的旧版更新：$legacy_arch" ;;
    esac

    legacy_work="$(mktemp -d)"
    trap 'rm -rf "$legacy_work"' 0 1 2 15
    say "检测到旧版 systemd 部署，下载最新 Release"
    curl -fsSL "$RELEASE_BASE_URL/$legacy_asset" -o "$legacy_work/$legacy_asset"
    curl -fsSL "$RELEASE_BASE_URL/SHA256SUMS.txt" -o "$legacy_work/SHA256SUMS.txt"
    legacy_expected="$(awk -v name="$legacy_asset" '$2 == name || $2 == ("*" name) {print $1; exit}' "$legacy_work/SHA256SUMS.txt")"
    legacy_actual="$(openssl dgst -sha256 "$legacy_work/$legacy_asset" | awk '{print $NF}')"
    if [ -z "$legacy_expected" ] || [ "$legacy_actual" != "$legacy_expected" ]; then
        fail "Refract Release 校验失败"
    fi

    legacy_stamp="$(date +%Y%m%d-%H%M%S)"
    legacy_backup="$legacy_dir/deploy-backups/auto-$legacy_stamp"
    mkdir -p "$legacy_dir/deploy-backups"
    mkdir -m 0700 "$legacy_backup"
    cp -p "$legacy_binary" "$legacy_backup/vps-url-gateway"
    install -m 0755 "$legacy_work/$legacy_asset" "$legacy_binary.next"

    if ! grep -q '^RESTART_ON_CONFIG_SAVE=' /etc/vps-url-gateway.env; then
        printf '\nRESTART_ON_CONFIG_SAVE=true\n' >>/etc/vps-url-gateway.env
    fi

    say "更新旧版服务"
    systemctl stop vps-url-gateway.service
    if ! mv "$legacy_binary.next" "$legacy_binary" || ! systemctl start vps-url-gateway.service; then
        cp -p "$legacy_backup/vps-url-gateway" "$legacy_binary"
        systemctl start vps-url-gateway.service || true
        fail "旧版服务启动失败，已恢复原二进制"
    fi

    legacy_attempt=0
    until curl -fsS http://127.0.0.1:8080/_gateway/health >/dev/null 2>&1; do
        legacy_attempt=$((legacy_attempt + 1))
        if [ "$legacy_attempt" -ge 30 ]; then
            systemctl stop vps-url-gateway.service || true
            cp -p "$legacy_backup/vps-url-gateway" "$legacy_binary"
            systemctl start vps-url-gateway.service || true
            fail "旧版服务健康检查失败，已恢复原二进制"
        fi
        sleep 1
    done

    if [ -d "$INSTALL_DIR/.git" ] && [ ! -e "$INSTALL_DIR/.env" ]; then
        legacy_incomplete="$INSTALL_DIR.incomplete-$legacy_stamp"
        mv "$INSTALL_DIR" "$legacy_incomplete"
        warn "已将未完成的新安装保留为 $legacy_incomplete"
    fi
    rm -rf "$legacy_work"
    trap - 0 1 2 15
    install_legacy_maintenance_socket
    say "旧版 systemd 部署已更新，配置、数据库和证书均已保留"
}

install_legacy_maintenance_socket() {
    say "配置低权限面板维护通道"
    cat >/etc/systemd/system/refract-maintenance.socket <<'EOF'
[Unit]
Description=Refract restricted maintenance socket

[Socket]
ListenStream=/run/refract-maintenance.sock
SocketUser=root
SocketGroup=vps-url-gateway
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=2
TriggerLimitIntervalSec=60s
TriggerLimitBurst=10
RemoveOnStop=true

[Install]
WantedBy=sockets.target
EOF
    cat >/etc/systemd/system/refract-maintenance@.service <<'EOF'
[Unit]
Description=Refract verified maintenance request
After=network-online.target

[Service]
Type=oneshot
User=root
Group=root
EnvironmentFile=/etc/vps-url-gateway.env
Environment=REFRACT_SYSTEMD_SERVICE=vps-url-gateway.service
ExecStart=/opt/vps-url-gateway/vps-url-gateway _maintenance-request
StandardInput=socket
StandardOutput=socket
StandardError=journal
TimeoutStartSec=3min
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/opt/vps-url-gateway
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
EOF
    systemctl daemon-reload
    systemctl enable --now refract-maintenance.socket >/dev/null
    systemctl restart vps-url-gateway.service
    maintenance_attempt=0
    until curl -fsS http://127.0.0.1:8080/_gateway/health >/dev/null 2>&1; do
        maintenance_attempt=$((maintenance_attempt + 1))
        if [ "$maintenance_attempt" -ge 30 ]; then
            fail "维护通道安装后服务健康检查失败"
        fi
        sleep 1
    done
}

say "检查系统依赖"
install_packages

if legacy_systemd_install; then
    update_legacy_systemd
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    install_docker
fi

if ! docker compose version >/dev/null 2>&1; then
    install_compose_plugin
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
    rc-update add docker default >/dev/null 2>&1 || true
    rc-service docker start >/dev/null 2>&1 || true
fi

docker info >/dev/null 2>&1 || fail "Docker 守护进程不可用，请先启动 Docker"
docker compose version >/dev/null 2>&1 || fail "缺少 Docker Compose v2 插件"

parent_dir="$(dirname "$INSTALL_DIR")"
mkdir -p "$parent_dir"

if [ -d "$INSTALL_DIR/.git" ]; then
    say "更新 $INSTALL_DIR"
    git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
elif [ -e "$INSTALL_DIR" ]; then
    fail "$INSTALL_DIR 已存在且不是 Refract Git 仓库，请更换 --install-dir"
else
    say "下载 Refract"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi

env_file="$INSTALL_DIR/.env"
if [ -f "$env_file" ]; then
    say "检测到已有配置，保留 $env_file"
else
    if [ -z "$domain" ]; then
        domain="$(ask "请输入已解析到本机的域名")"
    fi
    valid_domain "$domain" || fail "域名格式不正确：$domain"

    if [ -z "$upstream" ] && [ -z "$allowed_upstreams" ] && ! is_true "$public_proxy"; then
        upstream="$(ask "请输入默认 Emby/Jellyfin 地址（留空启用通用反代）")"
        if [ -z "$upstream" ]; then
            if ! has_interactive_terminal; then
                fail "非交互安装未配置默认上游；如需通用反代，请显式添加 --public-proxy"
            fi
            public_proxy=true
            inferred_public_proxy=1
        fi
    fi
    if [ -n "$upstream" ]; then
        valid_upstream "$upstream" || fail "上游必须是仅含协议和主机的 HTTP/HTTPS 地址"
        upstream="${upstream%/}"
    fi
    valid_host_list "$allowed_upstreams" || fail "初始上游列表格式不正确"
    valid_admin_user "$admin_user" || fail "管理员用户名只能包含字母、数字及 _ . @ -"

    if is_true "$public_proxy"; then
        warn "通用开放模式允许任何用户代理任意公网 HTTP/HTTPS 目标，可能被滥用。私网与保留地址仍默认阻止。"
        confirm_default=n
        if [ "$inferred_public_proxy" -eq 1 ]; then
            confirm_default=y
        fi
        if [ "$assume_yes" -ne 1 ] && ! confirm "确认启用通用开放模式" "$confirm_default"; then
            fail "已取消部署"
        fi
        public_proxy=true
    else
        public_proxy=false
        [ -n "$upstream" ] || [ -n "$allowed_upstreams" ] || fail "安全模式至少需要 --upstream 或 --allow-hosts"
    fi

    if is_true "$allow_private"; then
        warn "已允许访问内网目标，请确保该服务不会暴露给不受信任的用户。"
        if [ "$assume_yes" -ne 1 ] && ! confirm "确认允许内网目标" "n"; then
            fail "已取消部署"
        fi
        allow_private=true
    else
        allow_private=false
    fi

    signing_secret="$(random_hex)"
    session_secret="$(random_hex)"

    say "生成安全配置"
    umask 077
    cat >"$env_file" <<EOF
PROXY_DOMAIN=$domain
DEFAULT_UPSTREAM=$upstream
ALLOWED_UPSTREAMS=$allowed_upstreams
SIGNING_SECRET=$signing_secret
SIGNED_URL_TTL=24h
ALLOW_UNSIGNED_TARGETS=$public_proxy
ALLOW_PRIVATE_TARGETS=$allow_private
PASS_CLIENT_IP=false
DISABLE_CACHE=true
REWRITE_MAX_BYTES=8388608
DNS_CACHE_TTL=1m
DIAL_TIMEOUT=15s
RESPONSE_HEADER_TIMEOUT=60s
TZ=Asia/Shanghai
ADMIN_ENABLED=true
ADMIN_USERNAME=$admin_user
ADMIN_PASSWORD_HASH=
ADMIN_SESSION_SECRET=$session_secret
ADMIN_SESSION_TTL=12h
ADMIN_DATABASE_PATH=/data/gateway.db
ADMIN_BACKUP_DIR=/data/backups
GEOIP_LOOKUP_URL=https://ipwho.is/{ip}?fields=success,ip,country,country_code,region,latitude,longitude
GEOIP_LOOKUP_TIMEOUT=8s
GEOIP_LOOKUP_INTERVAL=1100ms
MAX_CONCURRENT_REQUESTS=256
MAX_CONCURRENT_PER_IP=64
MAX_DOWNLOAD_MBIT_PER_IP=0
EOF
    chmod 600 "$env_file"
fi

say "校验并启动服务"
cd "$INSTALL_DIR"
docker compose config --quiet
docker compose up -d --build --remove-orphans

attempt=0
until docker compose exec -T gateway wget -q -O /dev/null http://127.0.0.1:8080/_gateway/health 2>/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
        docker compose ps
        docker compose logs --tail=80 gateway caddy
        fail "服务未能在 120 秒内通过健康检查"
    fi
    sleep 2
done

configured_domain="$(sed -n 's/^PROXY_DOMAIN=//p' "$env_file" | head -n 1)"
say "部署完成"
printf '%s\n' \
    "管理初始化：https://$configured_domain/setup" \
    "管理登录：https://$configured_domain/login" \
    "运行状态：cd $INSTALL_DIR && docker compose ps" \
    "查看日志：cd $INSTALL_DIR && docker compose logs -f"
