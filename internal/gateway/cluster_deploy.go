package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type binaryHashCacheEntry struct {
	path    string
	size    int64
	modTime int64
	sha256  string
}

var (
	binaryHashCacheMu sync.Mutex
	binaryHashCache   = make(map[string]binaryHashCacheEntry)
)

func openBinaryWithSHA256Cached(path string) (*os.File, os.FileInfo, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, "", err
	}
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		_ = file.Close()
		if err == nil {
			err = fmt.Errorf("agent binary path is a directory")
		}
		return nil, nil, "", err
	}
	binaryHashCacheMu.Lock()
	if cached, ok := binaryHashCache[path]; ok && cached.size == info.Size() && cached.modTime == info.ModTime().UnixNano() {
		binaryHashCacheMu.Unlock()
		return file, info, cached.sha256, nil
	}
	binaryHashCacheMu.Unlock()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		_ = file.Close()
		return nil, nil, "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, nil, "", err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	binaryHashCacheMu.Lock()
	binaryHashCache[path] = binaryHashCacheEntry{
		path: path, size: info.Size(), modTime: info.ModTime().UnixNano(), sha256: digest,
	}
	binaryHashCacheMu.Unlock()
	return file, info, digest, nil
}

func fileSHA256Cached(path string) (string, os.FileInfo, error) {
	file, info, digest, err := openBinaryWithSHA256Cached(path)
	if err != nil {
		return "", nil, err
	}
	_ = file.Close()
	return digest, info, nil
}

func (c *clusterController) authenticateEnrollTokenReadOnly(r *http.Request) (edgeNodeRecord, bool) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if len(token) < 16 {
		return edgeNodeRecord{}, false
	}
	node, err := c.store.FindEdgeNodeByEnrollTokenHash(r.Context(), hashAgentToken(token))
	if err != nil {
		return edgeNodeRecord{}, false
	}
	if node.EnrollExpiresAt <= 0 || time.Now().Unix() > node.EnrollExpiresAt {
		return edgeNodeRecord{}, false
	}
	return node, true
}

func (c *clusterController) resolveControllerBaseURL(r *http.Request) string {
	if c.gateway.cfg.PublicBaseURL != nil {
		return strings.TrimRight(c.gateway.cfg.PublicBaseURL.String(), "/")
	}
	if base, err := publicBaseForRequest(c.gateway.cfg, r); err == nil && base != "" {
		return strings.TrimRight(base, "/")
	}
	return ""
}

func isSafeShellURL(raw string) bool {
	if raw == "" || len(raw) > 256 {
		return false
	}
	if strings.ContainsAny(raw, "'\"`$\\\r\n\t ;|&<>()") {
		return false
	}
	parsed, err := parseHTTPURL(raw)
	return err == nil && parsed.Host != ""
}

func isSafeShellToken(raw string) bool {
	if len(raw) < 16 || len(raw) > 128 {
		return false
	}
	for _, ch := range raw {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

func (c *clusterController) handleAgentInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	discoveryToken := strings.TrimSpace(r.URL.Query().Get("discovery"))
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if discoveryToken != "" {
		if !strings.HasPrefix(discoveryToken, "rf_dsc_") {
			http.Error(w, "# invalid cluster discovery token\nexit 1\n", http.StatusUnauthorized)
			return
		}
		token = discoveryToken
	}
	if !isSafeShellToken(token) {
		http.Error(w, "# invalid enrollment or discovery token\nexit 1\n", http.StatusUnauthorized)
		return
	}
	nodePublicDisplay := "由主控「域名入口」统一分配"
	if strings.HasPrefix(token, "rf_dsc_") {
		if _, ok := c.discovery.Verify(r.Context(), token); !ok {
			http.Error(w, "# cluster discovery token disabled or invalid\nexit 1\n", http.StatusUnauthorized)
			return
		}
	} else {
		node, ok := c.authenticateEnrollTokenReadOnly(r)
		if !ok {
			http.Error(w, "# enrollment token invalid or expired\nexit 1\n", http.StatusUnauthorized)
			return
		}
		if isSafeShellURL(node.PublicURL) {
			nodePublicDisplay = node.PublicURL
		}
	}
	controllerURL := c.resolveControllerBaseURL(r)
	if !isSafeShellURL(controllerURL) {
		http.Error(w, "# controller public URL unavailable\nexit 1\n", http.StatusBadRequest)
		return
	}

	tlsMode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tls")))
	autoTLS := tlsMode != "off" && tlsMode != "false" && tlsMode != "0"

	proxyPort := 8080
	if rawPort := strings.TrimSpace(r.URL.Query().Get("port")); rawPort != "" {
		if parsed, err := strconv.Atoi(rawPort); err == nil && parsed >= 1 && parsed <= 65535 {
			proxyPort = parsed
		}
	}

	var envBlock string
	if autoTLS {
		envBlock = fmt.Sprintf(`REFRACT_MODE=agent
REFRACT_AGENT_AUTO_TLS=true
LISTEN_ADDR=:80
REFRACT_AGENT_TLS_LISTEN_ADDR=:443
REFRACT_AGENT_CERT_DIR=/var/lib/refract-agent/certs
REFRACT_CONTROLLER_URL=%s
REFRACT_ENROLL_TOKEN=%s
REFRACT_AGENT_STATE_PATH=/var/lib/refract-agent/state.json`, controllerURL, token)
	} else {
		envBlock = fmt.Sprintf(`REFRACT_MODE=agent
REFRACT_AGENT_AUTO_TLS=false
LISTEN_ADDR=127.0.0.1:%d
TRUST_PROXY_HEADERS=true
REFRACT_CONTROLLER_URL=%s
REFRACT_ENROLL_TOKEN=%s
REFRACT_AGENT_STATE_PATH=/var/lib/refract-agent/state.json`, proxyPort, controllerURL, token)
	}

	var portCheckBlock string
	var healthProbeURL string
	if autoTLS {
		portCheckBlock = `if command -v ss >/dev/null 2>&1; then
  for P in 80 443; do
    CONFLICT="$(ss -H -tlnp "sport = :$P" 2>/dev/null | grep -v 'refract' || true)"
    if [ -n "$CONFLICT" ]; then
      echo "[Refract Agent] 端口 :$P 已被其他程序占用，AutoTLS 模式需要独占 80/443 端口：" >&2
      echo "$CONFLICT" >&2
      echo "[Refract Agent] 请先停止占用进程，或改用反代模式（安装链接附带 &tls=off）。" >&2
      exit 1
    fi
  done
fi`
		healthProbeURL = "http://127.0.0.1:80/_gateway/health"
	} else {
		portCheckBlock = fmt.Sprintf(`if command -v ss >/dev/null 2>&1; then
  CONFLICT="$(ss -H -tlnp "sport = :%d" 2>/dev/null | grep -v 'refract' || true)"
  if [ -n "$CONFLICT" ]; then
    echo "[Refract Agent] 本地端口 :%d 已被其他程序占用：" >&2
    echo "$CONFLICT" >&2
    echo "[Refract Agent] 请停止占用进程，或在安装链接中指定其他端口（&port=...）。" >&2
    exit 1
  fi
fi`, proxyPort, proxyPort)
		healthProbeURL = fmt.Sprintf("http://127.0.0.1:%d/_gateway/health", proxyPort)
	}

	script := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[Refract Agent] 请使用 root 或 sudo 运行此安装脚本。" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "[Refract Agent] 未检测到 systemctl，当前环境不支持一键 systemd 安装（请使用 Docker 或手动二进制模式）。" >&2
  exit 1
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "[Refract Agent] 不支持的架构: $RAW_ARCH" >&2; exit 1 ;;
esac

if [ "$OS" != "linux" ]; then
  echo "[Refract Agent] 一键 systemd 安装仅支持 Linux，当前系统: $OS" >&2
  exit 1
fi

%s

CONTROLLER_URL='%s'
ENROLL_TOKEN='%s'
INSTALL_DIR="/opt/refract-agent"
DATA_DIR="/var/lib/refract-agent"
BIN_PATH="$INSTALL_DIR/refract"
TMP_BIN="$(mktemp /tmp/refract-agent-bin.XXXXXX)"
TMP_HDR="$(mktemp /tmp/refract-agent-hdr.XXXXXX)"
trap 'rm -f "$TMP_BIN" "$TMP_HDR"' EXIT

echo "[Refract Agent] 正在从主控下载 ${OS}/${ARCH} 二进制..."
HTTP_CODE="$(curl -sS -L -D "$TMP_HDR" -o "$TMP_BIN" -w '%%{http_code}' "${CONTROLLER_URL}/_agent/api/v1/binary?os=${OS}&arch=${ARCH}&token=${ENROLL_TOKEN}")"
if [ "$HTTP_CODE" != "200" ]; then
  echo "[Refract Agent] 二进制下载失败 (HTTP $HTTP_CODE)，请确认主控存在对应架构二进制且 Token 未过期。" >&2
  exit 1
fi

EXPECTED_SHA="$(awk -F':' 'tolower($1)=="x-refract-sha256" {val=$2; gsub(/^[ \t]+|[ \t\r]+$/, "", val); print val}' "$TMP_HDR" | tail -n 1)"
if [ -z "$EXPECTED_SHA" ]; then
  echo "[Refract Agent] 主控未返回二进制校验摘要 X-Refract-SHA256，中止安装。" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
  ACTUAL_SHA="$(openssl dgst -sha256 "$TMP_BIN" | awk '{print $NF}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA="$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')"
else
  echo "[Refract Agent] 缺少 sha256sum/openssl/shasum 校验工具，拒绝继续安装。" >&2
  exit 1
fi
if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
  echo "[Refract Agent] SHA-256 校验失败: expected=$EXPECTED_SHA actual=$ACTUAL_SHA" >&2
  exit 1
fi
echo "[Refract Agent] 二进制 SHA-256 校验通过。"

install -d -m 0755 "$INSTALL_DIR"
install -d -m 0700 "$DATA_DIR" "$DATA_DIR/certs"
install -m 0755 "$TMP_BIN" "$BIN_PATH.new"
mv -f "$BIN_PATH.new" "$BIN_PATH"

# Fresh token install clears any stale agent state.json so re-enrollment succeeds cleanly.
rm -f "$DATA_DIR/state.json"

cat <<'EOF' > /etc/refract-agent.env
%s
EOF
chmod 0600 /etc/refract-agent.env

cat <<'EOF' > /etc/systemd/system/refract-agent.service
[Unit]
Description=Refract Edge Reverse Proxy Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/refract-agent.env
ExecStart=/opt/refract-agent/refract
WorkingDirectory=/var/lib/refract-agent
Restart=always
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable refract-agent.service >/dev/null 2>&1 || true
systemctl restart refract-agent.service

READY=0
for _ in 1 2 3 4 5 6 7 8; do
  if systemctl is-active --quiet refract-agent.service && curl -fsS --max-time 2 '%s' >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done

if [ "$READY" -eq 1 ] || systemctl is-active --quiet refract-agent.service; then
  echo "[Refract Agent] 部署完成并已上线！"
  echo "[Refract Agent] 节点入口: %s"
  echo "[Refract Agent] 查看日志: journalctl -u refract-agent -f"
else
  echo "[Refract Agent] 服务启动异常，最近日志如下：" >&2
  journalctl -u refract-agent -n 30 --no-pager >&2 || true
  exit 1
fi
`, portCheckBlock, controllerURL, token, envBlock, healthProbeURL, nodePublicDisplay)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="refract-agent-install.sh"`)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, script)
}

func (c *clusterController) resolveAgentBinaryPath(targetOS, targetArch string) (string, error) {
	if targetOS != "linux" && targetOS != "darwin" {
		return "", fmt.Errorf("unsupported os %q", targetOS)
	}
	if targetArch != "amd64" && targetArch != "arm64" {
		return "", fmt.Errorf("unsupported arch %q", targetArch)
	}
	if c.gateway.cfg.AgentBinaryDir != "" {
		candidate := filepath.Join(c.gateway.cfg.AgentBinaryDir, fmt.Sprintf("refract-%s-%s", targetOS, targetArch))
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	if targetOS == runtime.GOOS && targetArch == runtime.GOARCH {
		if exe, err := os.Executable(); err == nil && exe != "" {
			if resolved, evalErr := filepath.EvalSymlinks(exe); evalErr == nil {
				exe = resolved
			}
			if info, statErr := os.Stat(exe); statErr == nil && !info.IsDir() {
				return exe, nil
			}
		}
	}
	return "", fmt.Errorf("agent binary for %s/%s not found", targetOS, targetArch)
}

func (c *clusterController) handleAgentBinaryDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, authedAgent := c.authenticateAgent(r)
	_, authedEnroll := c.authenticateEnrollTokenReadOnly(r)
	_, authedDiscovery := c.discovery.Verify(r.Context(), r.URL.Query().Get("token"))
	if !authedDiscovery {
		_, authedDiscovery = c.discovery.Verify(r.Context(), r.URL.Query().Get("discovery"))
	}
	if !authedAgent && !authedEnroll && !authedDiscovery {
		writeGatewayError(w, http.StatusUnauthorized, "valid agent, enrollment, or discovery token required")
		return
	}
	targetOS := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("os")))
	targetArch := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("arch")))
	if targetOS == "" {
		targetOS = "linux"
	}
	if targetArch == "" {
		targetArch = "amd64"
	}
	binPath, err := c.resolveAgentBinaryPath(targetOS, targetArch)
	if err != nil {
		writeGatewayError(w, http.StatusNotFound, err.Error())
		return
	}
	file, info, digest, err := openBinaryWithSHA256Cached(binPath)
	if err != nil {
		writeGatewayError(w, http.StatusInternalServerError, "failed to open agent binary")
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Refract-SHA256", digest)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="refract-%s-%s"`, targetOS, targetArch))
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}
