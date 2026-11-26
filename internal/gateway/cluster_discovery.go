package gateway

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const clusterDiscoverySettingKey = "cluster_discovery_json"

type clusterDiscoveryStored struct {
	Enabled        bool   `json:"enabled"`
	EncryptedToken string `json:"encrypted_token"`
	DefaultGroup   string `json:"default_group"`
	DefaultRegion  string `json:"default_region"`
	UpdatedAt      int64  `json:"updated_at"`
}

type clusterDiscoveryView struct {
	Enabled       bool                `json:"enabled"`
	Token         string              `json:"token"`
	DefaultGroup  string              `json:"default_group"`
	DefaultRegion string              `json:"default_region"`
	UpdatedAt     int64               `json:"updated_at"`
	Commands      agentDeployCommands `json:"commands"`
}

type clusterDiscoveryManager struct {
	store  *telemetryStore
	cipher *tokenCipher
	mu     sync.Mutex
}

func newClusterDiscoveryManager(store *telemetryStore, secret []byte) (*clusterDiscoveryManager, error) {
	cipher, err := newScopedTokenCipher(secret, "cluster-discovery")
	if err != nil {
		return nil, err
	}
	return &clusterDiscoveryManager{store: store, cipher: cipher}, nil
}

func (m *clusterDiscoveryManager) loadOrInitLocked(ctx context.Context) (clusterDiscoveryStored, string, error) {
	var raw string
	err := m.store.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, clusterDiscoverySettingKey).Scan(&raw)
	if err == nil && strings.TrimSpace(raw) != "" {
		var stored clusterDiscoveryStored
		if unmarshalErr := json.Unmarshal([]byte(raw), &stored); unmarshalErr != nil {
			return clusterDiscoveryStored{}, "", fmt.Errorf("corrupted cluster discovery settings: %w", unmarshalErr)
		}
		if stored.EncryptedToken != "" {
			token, decErr := m.cipher.Decrypt(stored.EncryptedToken)
			if decErr != nil || !strings.HasPrefix(token, "rf_dsc_") {
				return clusterDiscoveryStored{}, "", errors.New("cluster discovery token decryption failed")
			}
			return stored, token, nil
		}
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return clusterDiscoveryStored{}, "", err
	}
	rawHex, err := generateRandomHex(24)
	if err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	token := "rf_dsc_" + rawHex
	enc, err := m.cipher.Encrypt(token)
	if err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	stored := clusterDiscoveryStored{
		Enabled:        true,
		EncryptedToken: enc,
		DefaultGroup:   "",
		DefaultRegion:  "",
		UpdatedAt:      time.Now().Unix(),
	}
	if err := m.saveLocked(ctx, stored); err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	return stored, token, nil
}

func (m *clusterDiscoveryManager) saveLocked(ctx context.Context, stored clusterDiscoveryStored) error {
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	_, err = m.store.db.ExecContext(ctx,
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		clusterDiscoverySettingKey, string(data), time.Now().Unix(),
	)
	return err
}

func (m *clusterDiscoveryManager) Get(ctx context.Context) (clusterDiscoveryStored, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadOrInitLocked(ctx)
}

func (m *clusterDiscoveryManager) Update(ctx context.Context, enabled bool, defaultGroup, defaultRegion string) (clusterDiscoveryStored, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, token, err := m.loadOrInitLocked(ctx)
	if err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	stored.Enabled = enabled
	stored.DefaultGroup = truncateRunes(strings.TrimSpace(defaultGroup), 48)
	stored.DefaultRegion = truncateRunes(strings.TrimSpace(defaultRegion), 48)
	stored.UpdatedAt = time.Now().Unix()
	if err := m.saveLocked(ctx, stored); err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	return stored, token, nil
}

func (m *clusterDiscoveryManager) Rotate(ctx context.Context) (clusterDiscoveryStored, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, _, err := m.loadOrInitLocked(ctx)
	if err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	rawHex, err := generateRandomHex(24)
	if err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	token := "rf_dsc_" + rawHex
	enc, err := m.cipher.Encrypt(token)
	if err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	stored.EncryptedToken = enc
	stored.UpdatedAt = time.Now().Unix()
	if err := m.saveLocked(ctx, stored); err != nil {
		return clusterDiscoveryStored{}, "", err
	}
	return stored, token, nil
}

func (m *clusterDiscoveryManager) loadOnlyLocked(ctx context.Context) (clusterDiscoveryStored, string, bool, error) {
	var raw string
	err := m.store.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, clusterDiscoverySettingKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || strings.TrimSpace(raw) == "" {
		return clusterDiscoveryStored{}, "", false, nil
	}
	if err != nil {
		return clusterDiscoveryStored{}, "", false, err
	}
	var stored clusterDiscoveryStored
	if unmarshalErr := json.Unmarshal([]byte(raw), &stored); unmarshalErr != nil {
		return clusterDiscoveryStored{}, "", false, fmt.Errorf("corrupted cluster discovery settings: %w", unmarshalErr)
	}
	if stored.EncryptedToken == "" {
		return clusterDiscoveryStored{}, "", false, nil
	}
	token, decErr := m.cipher.Decrypt(stored.EncryptedToken)
	if decErr != nil || !strings.HasPrefix(token, "rf_dsc_") {
		return clusterDiscoveryStored{}, "", false, errors.New("cluster discovery token decryption failed")
	}
	return stored, token, true, nil
}

func (m *clusterDiscoveryManager) Verify(ctx context.Context, candidate string) (clusterDiscoveryStored, bool) {
	if m == nil {
		return clusterDiscoveryStored{}, false
	}
	candidate = strings.TrimSpace(candidate)
	if !strings.HasPrefix(candidate, "rf_dsc_") || len(candidate) < 24 {
		return clusterDiscoveryStored{}, false
	}
	m.mu.Lock()
	stored, token, found, err := m.loadOnlyLocked(ctx)
	m.mu.Unlock()
	if err != nil || !found || !stored.Enabled || token == "" {
		return clusterDiscoveryStored{}, false
	}
	if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) != 1 {
		return clusterDiscoveryStored{}, false
	}
	return stored, true
}

func buildDiscoveryDeployCommands(controllerURL, discoveryToken string) agentDeployCommands {
	controllerURL = safeDeployControllerURL(controllerURL)
	oneClickAutoTLS := fmt.Sprintf(`curl -fsSL %s | { [ "$(id -u)" -eq 0 ] && bash || sudo bash; }`, shellSingleQuote(controllerURL+"/_agent/api/v1/install.sh?discovery="+discoveryToken))
	oneClickProxy := fmt.Sprintf(`curl -fsSL %s | { [ "$(id -u)" -eq 0 ] && bash || sudo bash; }`, shellSingleQuote(controllerURL+"/_agent/api/v1/install.sh?discovery="+discoveryToken+"&tls=off"))
	cliCmd := fmt.Sprintf("REFRACT_MODE=agent REFRACT_CONTROLLER_URL=%s REFRACT_ENROLL_TOKEN=%s REFRACT_AGENT_STATE_PATH=/var/lib/refract-agent/state.json LISTEN_ADDR=127.0.0.1:8080 ./refract", shellSingleQuote(controllerURL), shellSingleQuote(discoveryToken))
	dockerCmd := fmt.Sprintf(`docker run -d --name refract-agent --restart unless-stopped \
  -p 80:80 -p 443:443 \
  -v refract-agent-data:/data \
  -e REFRACT_MODE=agent \
  -e REFRACT_AGENT_AUTO_TLS=true \
  -e LISTEN_ADDR=:80 \
  -e REFRACT_AGENT_TLS_LISTEN_ADDR=:443 \
  -e REFRACT_AGENT_CERT_DIR=/data/certs \
  -e REFRACT_CONTROLLER_URL=%s \
  -e REFRACT_ENROLL_TOKEN=%s \
  -e REFRACT_AGENT_STATE_PATH=/data/state.json \
  ghcr.io/t-matrix/refract:latest`, shellSingleQuote(controllerURL), shellSingleQuote(discoveryToken))
	return agentDeployCommands{
		EnrollToken:     discoveryToken,
		ControllerURL:   controllerURL,
		OneClickAutoTLS: oneClickAutoTLS,
		OneClickProxy:   oneClickProxy,
		DockerCommand:   dockerCmd,
		CLICommand:      cliCmd,
	}
}

func (a *adminServer) handleClusterDiscovery(w http.ResponseWriter, r *http.Request) {
	if a.gateway.cluster == nil || a.gateway.cluster.discovery == nil {
		a.writeError(w, http.StatusServiceUnavailable, "cluster discovery unavailable")
		return
	}
	ctrlURL := a.resolveControllerURL(r)
	switch r.Method {
	case http.MethodGet:
		stored, token, err := a.gateway.cluster.discovery.Get(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to load discovery settings")
			return
		}
		a.writeJSON(w, http.StatusOK, clusterDiscoveryView{
			Enabled:       stored.Enabled,
			Token:         token,
			DefaultGroup:  stored.DefaultGroup,
			DefaultRegion: stored.DefaultRegion,
			UpdatedAt:     stored.UpdatedAt,
			Commands:      buildDiscoveryDeployCommands(ctrlURL, token),
		})
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req struct {
			Enabled       bool   `json:"enabled"`
			DefaultGroup  string `json:"default_group"`
			DefaultRegion string `json:"default_region"`
		}
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		stored, token, err := a.gateway.cluster.discovery.Update(r.Context(), req.Enabled, req.DefaultGroup, req.DefaultRegion)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to save discovery settings")
			return
		}
		a.auditRequest(r, "edge_node.discovery", "cluster", fmt.Sprintf("enabled=%t group=%q region=%q", stored.Enabled, stored.DefaultGroup, stored.DefaultRegion), true)
		a.writeJSON(w, http.StatusOK, clusterDiscoveryView{
			Enabled:       stored.Enabled,
			Token:         token,
			DefaultGroup:  stored.DefaultGroup,
			DefaultRegion: stored.DefaultRegion,
			UpdatedAt:     stored.UpdatedAt,
			Commands:      buildDiscoveryDeployCommands(ctrlURL, token),
		})
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handleClusterDiscoveryRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if a.gateway.cluster == nil || a.gateway.cluster.discovery == nil {
		a.writeError(w, http.StatusServiceUnavailable, "cluster discovery unavailable")
		return
	}
	stored, token, err := a.gateway.cluster.discovery.Rotate(r.Context())
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "failed to rotate discovery token")
		return
	}
	a.auditRequest(r, "edge_node.discovery.rotate", "cluster", "rotated discovery token", true)
	a.writeJSON(w, http.StatusOK, clusterDiscoveryView{
		Enabled:       stored.Enabled,
		Token:         token,
		DefaultGroup:  stored.DefaultGroup,
		DefaultRegion: stored.DefaultRegion,
		UpdatedAt:     stored.UpdatedAt,
		Commands:      buildDiscoveryDeployCommands(a.resolveControllerURL(r), token),
	})
}
