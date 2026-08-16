#!/bin/sh
set -eu

REPO_URL="${REFRACT_REPO_URL:-https://github.com/T-Matrix/Refract.git}"
BRANCH="${REFRACT_BRANCH:-main}"
INSTALL_DIR="${REFRACT_INSTALL_DIR:-/opt/refract}"

domain="${REFRACT_DOMAIN:-}"
upstream="${REFRACT_UPSTREAM:-}"
allowed_upstreams="${REFRACT_ALLOWED_UPSTREAMS:-}"
admin_user="${REFRACT_ADMIN_USER:-admin}"
public_proxy="${REFRACT_PUBLIC_PROXY:-false}"
allow_private="${REFRACT_ALLOW_PRIVATE_TARGETS:-false}"
assume_yes=0

usage() {
    cat <<'EOF'
Refract 一键部署脚本

用法：
  install.sh [选项]

选项：
  --domain DOMAIN          已解析到 VPS 的域名
  --upstream URL           默认上游，例如 https://emby.example.com
  --allow-hosts LIST       可直接访问的初始上游，逗号分隔
  --admin-user USER        初始管理员用户名，默认 admin
  --public-proxy           允许代理任意公网 HTTP/HTTPS 目标
  --allow-private          允许访问内网目标（高风险）
  --install-dir DIR        安装目录，默认 /opt/refract
  --yes                    跳过确认，适合自动化部署
  -h, --help               显示帮助

环境变量：
  REFRACT_REPO_URL、REFRACT_BRANCH、REFRACT_INSTALL_DIR
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
    installer="$(mktemp)"
    curl -fsSL https://get.docker.com -o "$installer"
    sh "$installer"
    rm -f "$installer"
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

say "检查系统依赖"
install_packages

if ! command -v docker >/dev/null 2>&1; then
    install_docker
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
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
        upstream="$(ask "请输入默认 Emby/Jellyfin 地址（不含末尾斜杠）")"
    fi
    if [ -n "$upstream" ]; then
        valid_upstream "$upstream" || fail "上游必须是仅含协议和主机的 HTTP/HTTPS 地址"
        upstream="${upstream%/}"
    fi
    valid_host_list "$allowed_upstreams" || fail "初始上游列表格式不正确"
    valid_admin_user "$admin_user" || fail "管理员用户名只能包含字母、数字及 _ . @ -"

    if is_true "$public_proxy"; then
        warn "通用开放模式允许任何用户代理任意公网 HTTP/HTTPS 目标，可能被滥用。私网与保留地址仍默认阻止。"
        if [ "$assume_yes" -ne 1 ] && ! confirm "确认启用通用开放模式" "n"; then
            fail "已取消部署"
        fi
        public_proxy=true
    else
        public_proxy=false
        if [ -z "$upstream" ] && [ -z "$allowed_upstreams" ]; then
            fail "安全模式至少需要 --upstream 或 --allow-hosts"
        fi
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
MAX_CONCURRENT_REQUESTS=64
MAX_CONCURRENT_PER_IP=12
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
