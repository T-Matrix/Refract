package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	playbackSessionActiveTTL   = 90 * time.Second
	playbackMetadataCacheLimit = 4096
	playbackUserCacheLimit     = 2048
	playbackMaxActiveSessions  = 256
	playbackHistoryRetention   = 30 * 24 * time.Hour
	playbackHistoryMaxRows     = 2000
	playbackPeekBodyLimit      = 32 << 10
	playbackKickBlockTTL       = 60 * time.Second
	playbackRedirectTTL        = 30 * time.Minute
	playbackRedirectCacheLimit = 4096
)

var (
	reEmbyVideoPath        = regexp.MustCompile(`(?i)^(?:/[^/?#]+)?(?:/emby)?/(?:videos|audio)/([^/?#]+)/(.+)$`)
	reEmbyItemDownloadPath = regexp.MustCompile(`(?i)^(?:/[^/?#]+)?(?:/emby)?/items/([^/?#]+)/(?:download|playbackinfo|file)(?:/|$)`)
	reEmbyUserItemPath     = regexp.MustCompile(`(?i)^(?:/[^/?#]+)?(?:/emby)?/users/([^/?#]+)/items/([^/?#]+)(?:/|$)`)
	reEmbyUserPath         = regexp.MustCompile(`(?i)^(?:/[^/?#]+)?(?:/emby)?/users/([^/?#]+)(?:/|$)`)
	reEmbyPlayingPath      = regexp.MustCompile(`(?i)^(?:/[^/?#]+)?(?:/emby)?/sessions/playing(?:/(progress|stopped))?/?$`)
	reSeasonEpisode        = regexp.MustCompile(`(?i)\bS(\d{1,2})E(\d{1,3})\b`)
	reResolutionTag        = regexp.MustCompile(`(?i)\b(2160p|4k|1080p|1080i|720p|480p)\b`)
	reDispositionFilename  = regexp.MustCompile(`(?i)filename\*?=(?:UTF-8''|"?)([^";\r\n]+)`)
)

type cachedMediaItem struct {
	ItemID         string
	MediaType      string
	Title          string
	SeriesName     string
	SeasonNumber   int
	EpisodeNumber  int
	ProductionYear int
	DurationSec    int64
	VideoQuality   string
	Container      string
	Bitrate        int64
	FromFilename   bool
	UpdatedAt      time.Time
}

type playbackSessionSnapshot struct {
	SessionKey     string `json:"session_key"`
	NodeID         string `json:"node_id,omitempty"`
	NodeName       string `json:"node_name,omitempty"`
	UserName       string `json:"user_name,omitempty"`
	ClientIP       string `json:"client_ip"`
	Location       string `json:"location,omitempty"`
	ClientName     string `json:"client_name,omitempty"`
	DeviceName     string `json:"device_name,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
	UpstreamHost   string `json:"upstream_host"`
	EmbyServerName string `json:"emby_server_name,omitempty"`
	ItemID         string `json:"item_id,omitempty"`
	MediaType      string `json:"media_type,omitempty"`
	Title          string `json:"title"`
	SeriesName     string `json:"series_name,omitempty"`
	SeasonNumber   int    `json:"season_number,omitempty"`
	EpisodeNumber  int    `json:"episode_number,omitempty"`
	ProductionYear int    `json:"production_year,omitempty"`
	VideoQuality   string `json:"video_quality,omitempty"`
	Container      string `json:"container,omitempty"`
	PlayMethod     string `json:"play_method,omitempty"`
	PositionSec    int64  `json:"position_sec,omitempty"`
	DurationSec    int64  `json:"duration_sec,omitempty"`
	ProgressPct    int    `json:"progress_pct,omitempty"`
	Paused         bool   `json:"paused,omitempty"`
	DownloadBPS    int64  `json:"download_bps"`
	BytesOut       int64  `json:"bytes_out"`
	ActiveStreams  int    `json:"active_streams"`
	FlowID         string `json:"flow_id,omitempty"`
	StartedAt      int64  `json:"started_at"`
	LastSeenAt     int64  `json:"last_seen_at"`
}

type watchHistoryRecord struct {
	SessionKey     string `json:"session_key"`
	NodeID         string `json:"node_id,omitempty"`
	NodeName       string `json:"node_name,omitempty"`
	UserName       string `json:"user_name,omitempty"`
	ClientIP       string `json:"client_ip"`
	Location       string `json:"location,omitempty"`
	ClientName     string `json:"client_name,omitempty"`
	DeviceName     string `json:"device_name,omitempty"`
	UpstreamHost   string `json:"upstream_host"`
	EmbyServerName string `json:"emby_server_name,omitempty"`
	ItemID         string `json:"item_id,omitempty"`
	MediaType      string `json:"media_type,omitempty"`
	Title          string `json:"title"`
	SeriesName     string `json:"series_name,omitempty"`
	SeasonNumber   int    `json:"season_number,omitempty"`
	EpisodeNumber  int    `json:"episode_number,omitempty"`
	ProductionYear int    `json:"production_year,omitempty"`
	VideoQuality   string `json:"video_quality,omitempty"`
	PlayMethod     string `json:"play_method,omitempty"`
	PositionSec    int64  `json:"position_sec,omitempty"`
	DurationSec    int64  `json:"duration_sec,omitempty"`
	ProgressPct    int    `json:"progress_pct,omitempty"`
	BytesOut       int64  `json:"bytes_out"`
	StartedAt      int64  `json:"started_at"`
	LastSeenAt     int64  `json:"last_seen_at"`
}

type playbackSummary struct {
	WatchingCount    int   `json:"watching_count"`
	UniqueUsers      int   `json:"unique_users"`
	TotalDownloadBPS int64 `json:"total_download_bps"`
	History24h       int   `json:"history_24h"`
}

type playbackSessionEntry struct {
	key            string
	userName       string
	userID         string
	clientIP       string
	clientName     string
	deviceName     string
	deviceID       string
	upstreamHost   string
	itemID         string
	mediaSourceID  string
	playSessionID  string
	mediaType      string
	title          string
	seriesName     string
	seasonNumber   int
	episodeNumber  int
	productionYear int
	videoQuality   string
	container      string
	playMethod     string
	positionSec    int64
	durationSec    int64
	paused         bool
	stopped        bool
	closedBytesOut int64
	flows          map[string]*connectionFlow
	startedAt      time.Time
	lastSeenAt     time.Time
}

type playbackRequestMeta struct {
	ClientIP      string
	DeviceID      string
	DeviceName    string
	ClientName    string
	UpstreamHost  string
	Scheme        string
	Path          string
	RawQuery      string
	Token         string
	TokenHash     string
	UserID        string
	DialAddresses []string
	Flow          *connectionFlow
}

type playbackRedirectBinding struct {
	clientIP     string
	upstreamHost string
	itemID       string
	deviceID     string
	deviceName   string
	clientName   string
	token        string
	tokenHash    string
	userID       string
	expiresAt    time.Time
}

type playbackTracker struct {
	mu            sync.RWMutex
	items         map[string]cachedMediaItem // key: host + "|" + itemID
	itemAliases   map[string]string          // key: host + "|" + aliasItemID -> canonical itemID
	sourceToItem  map[string]string          // key: host + "|" + mediaSourceID -> itemID
	playToItem    map[string]string          // key: host + "|" + playSessionID -> itemID
	usersByID     map[string]string          // key: host + "|" + userID -> userName
	usersByToken  map[string]string          // key: host + "|" + tokenHash -> userName
	usersByDevice map[string]string          // key: host + "|" + deviceID -> userName
	sessions      map[string]*playbackSessionEntry
	flowSessions  map[string]*playbackSessionEntry // flow.id -> owning playback session
	redirects     map[string]playbackRedirectBinding
	kicked        map[string]time.Time // temporary cooldown blocks for terminated playback sessions/streams
	lookups       map[string]time.Time // negative / inflight cache for background item fetches
	fetchSem      chan struct{}
}

func newPlaybackTracker() *playbackTracker {
	return &playbackTracker{
		items:         make(map[string]cachedMediaItem),
		itemAliases:   make(map[string]string),
		sourceToItem:  make(map[string]string),
		playToItem:    make(map[string]string),
		usersByID:     make(map[string]string),
		usersByToken:  make(map[string]string),
		usersByDevice: make(map[string]string),
		sessions:      make(map[string]*playbackSessionEntry),
		flowSessions:  make(map[string]*playbackSessionEntry),
		redirects:     make(map[string]playbackRedirectBinding),
		kicked:        make(map[string]time.Time),
		lookups:       make(map[string]time.Time),
		fetchSem:      make(chan struct{}, 8),
	}
}

func extractEmbyRequestCredentials(r *http.Request, target *url.URL) (token, tokenHash, userID string) {
	if r != nil {
		for _, hdr := range []string{"X-Emby-Token", "X-MediaBrowser-Token"} {
			if v := strings.TrimSpace(r.Header.Get(hdr)); v != "" {
				token = v
				break
			}
		}
		if token == "" {
			for _, hdr := range []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "Authorization"} {
				raw := r.Header.Get(hdr)
				if raw == "" {
					continue
				}
				if tok := extractAuthParam(raw, "Token"); tok != "" {
					token = tok
					break
				}
			}
		}
	}
	if target != nil {
		q := target.Query()
		if token == "" {
			for _, k := range []string{"api_key", "X-Emby-Token", "X-MediaBrowser-Token", "ApiKey"} {
				if v := strings.TrimSpace(q.Get(k)); v != "" {
					token = v
					break
				}
			}
		}
		for _, k := range []string{"UserId", "userId", "user_id"} {
			if v := strings.TrimSpace(q.Get(k)); v != "" {
				userID = v
				break
			}
		}
		if userID == "" {
			if m := reEmbyUserItemPath.FindStringSubmatch(target.EscapedPath()); len(m) == 3 {
				userID = m[1]
			} else if m := reEmbyUserPath.FindStringSubmatch(target.EscapedPath()); len(m) == 2 {
				cand := strings.ToLower(m[1])
				if cand != "authenticatebyname" && cand != "public" && cand != "me" {
					userID = m[1]
				}
			}
		}
	}
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		tokenHash = hex.EncodeToString(sum[:12])
	}
	return token, tokenHash, userID
}

func extractAuthParam(header, key string) string {
	fields := parseMediaBrowserParameters(header)
	return strings.TrimSpace(fields[strings.ToLower(strings.TrimSpace(key))])
}

func isEmbyStreamSubpath(tail string) bool {
	lower := strings.ToLower(strings.Trim(strings.TrimSpace(tail), "/"))
	if lower == "" {
		return false
	}
	for _, excluded := range []string{"/subtitles/", "/trickplay/", "/images/", "/attachments/"} {
		if strings.Contains(lower, excluded) {
			return false
		}
	}
	firstSeg, _, _ := strings.Cut(lower, "/")
	switch firstSeg {
	case "additionalparts", "alternatesources", "subtitles", "trickplay", "images", "attachments",
		"similar", "playbackinfo", "themevideos", "themesongs", "localtrailers", "specialfeatures",
		"ancestors", "intros", "chapters":
		return false
	}
	switch ext := strings.ToLower(path.Ext(lower)); ext {
	case ".srt", ".vtt", ".ass", ".ssa", ".sub", ".idx", ".sup", ".bif",
		".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg", ".json", ".xml", ".nfo", ".txt":
		return false
	case ".m3u8", ".mp4", ".mkv", ".ts", ".m4s", ".webm", ".mov", ".m2ts", ".avi", ".flv",
		".mp3", ".flac", ".aac", ".ogg", ".m4a", ".opus", ".wav":
		return true
	}
	switch {
	case firstSeg == "stream" || strings.HasPrefix(firstSeg, "stream."),
		firstSeg == "original" || strings.HasPrefix(firstSeg, "original."),
		firstSeg == "universal" || strings.HasPrefix(firstSeg, "universal."),
		firstSeg == "hls" || firstSeg == "hls1" || firstSeg == "hlsdynamic",
		firstSeg == "master.m3u8" || firstSeg == "main.m3u8" || firstSeg == "live.m3u8" || firstSeg == "index.m3u8":
		return true
	}
	return false
}

func extractEmbyItemIDFromPath(p string) (itemID string, isStream bool, isPlaybackInfo bool) {
	if m := reEmbyVideoPath.FindStringSubmatch(p); len(m) == 3 && isEmbyStreamSubpath(m[2]) {
		return m[1], true, false
	}
	if m := reEmbyItemDownloadPath.FindStringSubmatch(p); len(m) == 2 {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "/playbackinfo") {
			return m[1], false, true
		}
		return m[1], true, false
	}
	return "", false, false
}

func isEmbyPlayingReportPath(p string) (action string, ok bool) {
	m := reEmbyPlayingPath.FindStringSubmatch(p)
	if len(m) == 0 {
		return "", false
	}
	switch strings.ToLower(m[1]) {
	case "progress":
		return "progress", true
	case "stopped":
		return "stopped", true
	default:
		return "start", true
	}
}

func playbackCacheKey(host, id string) string {
	return strings.ToLower(strings.TrimSpace(host)) + "|" + strings.TrimSpace(id)
}

func (p *playbackTracker) resolveUserNameLocked(host, userID, tokenHash, deviceID string) string {
	if userID != "" {
		if u := p.usersByID[playbackCacheKey(host, userID)]; u != "" {
			return u
		}
	}
	if tokenHash != "" {
		if u := p.usersByToken[playbackCacheKey(host, tokenHash)]; u != "" {
			return u
		}
	}
	if deviceID != "" {
		if u := p.usersByDevice[playbackCacheKey(host, deviceID)]; u != "" {
			return u
		}
	}
	return ""
}

func (p *playbackTracker) rememberUserLocked(host, userID, userName, tokenHash, deviceID string) {
	userName = truncateRunes(strings.TrimSpace(userName), 80)
	if userName == "" || host == "" {
		return
	}
	if len(p.usersByID) > playbackUserCacheLimit {
		clear(p.usersByID)
	}
	if len(p.usersByToken) > playbackUserCacheLimit {
		clear(p.usersByToken)
	}
	if len(p.usersByDevice) > playbackUserCacheLimit {
		clear(p.usersByDevice)
	}
	if userID != "" {
		p.usersByID[playbackCacheKey(host, userID)] = userName
	}
	if tokenHash != "" {
		p.usersByToken[playbackCacheKey(host, tokenHash)] = userName
	}
	if deviceID != "" {
		p.usersByDevice[playbackCacheKey(host, deviceID)] = userName
	}
}

func (p *playbackTracker) upsertItemLocked(host string, item cachedMediaItem) {
	if host == "" || item.ItemID == "" {
		return
	}
	key := playbackCacheKey(host, item.ItemID)
	prev, exists := p.items[key]
	if !exists && len(p.items) >= playbackMetadataCacheLimit {
		// Evict oldest ~25% entries to keep memory strictly bounded.
		type pair struct {
			k string
			t time.Time
		}
		all := make([]pair, 0, len(p.items))
		for k, v := range p.items {
			all = append(all, pair{k: k, t: v.UpdatedAt})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
		for i := 0; i < len(all)/4 && i < len(all); i++ {
			delete(p.items, all[i].k)
		}
	}
	merged := prev
	merged.ItemID = item.ItemID
	allowOverwriteText := !item.FromFilename || !exists || prev.FromFilename || prev.Title == ""
	if allowOverwriteText {
		if item.Title != "" {
			merged.Title = truncateRunes(item.Title, 140)
		}
		if item.MediaType != "" {
			merged.MediaType = item.MediaType
		}
		if item.SeriesName != "" {
			merged.SeriesName = truncateRunes(item.SeriesName, 120)
		}
		if item.SeasonNumber > 0 {
			merged.SeasonNumber = item.SeasonNumber
		}
		if item.EpisodeNumber > 0 {
			merged.EpisodeNumber = item.EpisodeNumber
		}
		if !item.FromFilename {
			merged.FromFilename = false
		} else if !exists {
			merged.FromFilename = true
		}
	} else {
		if merged.MediaType == "" && item.MediaType != "" {
			merged.MediaType = item.MediaType
		}
		if merged.SeriesName == "" && item.SeriesName != "" {
			merged.SeriesName = truncateRunes(item.SeriesName, 120)
		}
		if merged.SeasonNumber == 0 && item.SeasonNumber > 0 {
			merged.SeasonNumber = item.SeasonNumber
		}
		if merged.EpisodeNumber == 0 && item.EpisodeNumber > 0 {
			merged.EpisodeNumber = item.EpisodeNumber
		}
	}
	if item.ProductionYear > 0 {
		merged.ProductionYear = item.ProductionYear
	}
	if item.DurationSec > 0 {
		merged.DurationSec = item.DurationSec
	}
	if item.VideoQuality != "" {
		merged.VideoQuality = truncateRunes(item.VideoQuality, 48)
	}
	if item.Container != "" {
		merged.Container = truncateRunes(item.Container, 16)
	}
	if item.Bitrate > 0 {
		merged.Bitrate = item.Bitrate
	}
	merged.UpdatedAt = time.Now()
	p.items[key] = merged

	// Propagate newly discovered metadata onto any live session watching this ItemID.
	for _, sess := range p.sessions {
		if strings.EqualFold(sess.upstreamHost, host) && sess.itemID == item.ItemID {
			applyItemToSession(sess, merged)
		}
	}
}

func applyItemToSession(sess *playbackSessionEntry, item cachedMediaItem) {
	if item.Title != "" && (sess.title == "" || strings.HasPrefix(sess.title, "媒体 #") || item.SeriesName != "" || item.MediaType != "") {
		sess.title = item.Title
	}
	if item.MediaType != "" {
		sess.mediaType = item.MediaType
	}
	if item.SeriesName != "" {
		sess.seriesName = item.SeriesName
	}
	if item.SeasonNumber > 0 {
		sess.seasonNumber = item.SeasonNumber
	}
	if item.EpisodeNumber > 0 {
		sess.episodeNumber = item.EpisodeNumber
	}
	if item.ProductionYear > 0 {
		sess.productionYear = item.ProductionYear
	}
	if item.DurationSec > 0 && sess.durationSec <= 0 {
		sess.durationSec = item.DurationSec
	}
	if item.VideoQuality != "" {
		sess.videoQuality = item.VideoQuality
	}
	if item.Container != "" {
		sess.container = item.Container
	}
	if sess.title != "" {
		title, sub := formatPlaybackFlowDisplay(sess)
		for _, f := range sess.flows {
			f.SetMediaInfo(title, sub)
		}
	}
}

func formatPlaybackFlowDisplay(sess *playbackSessionEntry) (title, sub string) {
	if sess == nil {
		return "", ""
	}
	if sess.seriesName != "" {
		title = sess.seriesName
		if sess.seasonNumber > 0 && sess.episodeNumber > 0 {
			sub = fmt.Sprintf("S%02dE%02d", sess.seasonNumber, sess.episodeNumber)
			if sess.title != "" && !strings.EqualFold(sess.title, sess.seriesName) {
				sub += " · " + sess.title
			}
		} else if sess.title != "" && !strings.EqualFold(sess.title, sess.seriesName) {
			sub = sess.title
		}
	} else {
		title = sess.title
		if sess.productionYear > 0 {
			sub = strconv.Itoa(sess.productionYear)
		}
	}
	if sess.videoQuality != "" {
		if sub != "" {
			sub += " · " + sess.videoQuality
		} else {
			sub = sess.videoQuality
		}
	}
	return truncateRunes(title, 120), truncateRunes(sub, 120)
}

func sanitizeSessionKeyPart(v string) string {
	return strings.ReplaceAll(strings.TrimSpace(v), "|", "_")
}

func (p *playbackTracker) sessionKeyFor(meta playbackRequestMeta, itemID string) string {
	identity := sanitizeSessionKeyPart(meta.DeviceID)
	if identity == "" {
		identity = strings.ToLower(sanitizeSessionKeyPart(meta.ClientName))
	}
	if identity == "" {
		identity = "generic"
	}
	return fmt.Sprintf("%s|%s|%s|%s",
		normalizeTelemetryClientIP(meta.ClientIP),
		identity,
		strings.ToLower(sanitizeSessionKeyPart(meta.UpstreamHost)),
		sanitizeSessionKeyPart(itemID),
	)
}

func playbackUsersCompatible(userIDA, userNameA, userIDB, userNameB string) bool {
	userIDA = strings.TrimSpace(userIDA)
	userIDB = strings.TrimSpace(userIDB)
	if userIDA != "" && userIDB != "" && !strings.EqualFold(userIDA, userIDB) {
		return false
	}
	userNameA = strings.TrimSpace(userNameA)
	userNameB = strings.TrimSpace(userNameB)
	if userNameA != "" && userNameB != "" && !strings.EqualFold(userNameA, userNameB) {
		return false
	}
	return true
}

func (p *playbackTracker) detachSessionFlowsLocked(sess *playbackSessionEntry) {
	if sess == nil || len(p.flowSessions) == 0 {
		return
	}
	for fid := range sess.flows {
		if cur := p.flowSessions[fid]; cur == sess {
			delete(p.flowSessions, fid)
		}
	}
}

func playbackClientsCompatible(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	return a == "" || b == "" || strings.EqualFold(a, b)
}

func mergePlaybackSessionsLocked(p *playbackTracker, dst, src *playbackSessionEntry) {
	if dst == nil || src == nil || dst == src {
		return
	}
	if src.closedBytesOut > 0 {
		dst.closedBytesOut += src.closedBytesOut
	}
	if !src.startedAt.IsZero() && (dst.startedAt.IsZero() || src.startedAt.Before(dst.startedAt)) {
		dst.startedAt = src.startedAt
	}
	if src.lastSeenAt.After(dst.lastSeenAt) {
		dst.lastSeenAt = src.lastSeenAt
	}
	if dst.userName == "" && src.userName != "" {
		dst.userName = src.userName
	}
	if dst.userID == "" && src.userID != "" {
		dst.userID = src.userID
	}
	if dst.clientName == "" && src.clientName != "" {
		dst.clientName = src.clientName
	}
	if dst.deviceName == "" && src.deviceName != "" {
		dst.deviceName = src.deviceName
	}
	if dst.mediaSourceID == "" && src.mediaSourceID != "" {
		dst.mediaSourceID = src.mediaSourceID
	}
	if dst.playSessionID == "" && src.playSessionID != "" {
		dst.playSessionID = src.playSessionID
	}
	if dst.mediaType == "" && src.mediaType != "" {
		dst.mediaType = src.mediaType
	}
	if (dst.title == "" || strings.HasPrefix(dst.title, "媒体 #")) && src.title != "" && !strings.HasPrefix(src.title, "媒体 #") {
		dst.title = src.title
	}
	if dst.seriesName == "" && src.seriesName != "" {
		dst.seriesName = src.seriesName
	}
	if dst.seasonNumber == 0 && src.seasonNumber > 0 {
		dst.seasonNumber = src.seasonNumber
	}
	if dst.episodeNumber == 0 && src.episodeNumber > 0 {
		dst.episodeNumber = src.episodeNumber
	}
	if dst.productionYear == 0 && src.productionYear > 0 {
		dst.productionYear = src.productionYear
	}
	if dst.videoQuality == "" && src.videoQuality != "" {
		dst.videoQuality = src.videoQuality
	}
	if dst.container == "" && src.container != "" {
		dst.container = src.container
	}
	if dst.playMethod == "" && src.playMethod != "" {
		dst.playMethod = src.playMethod
	} else if src.playMethod == "DirectStream" && dst.playMethod == "DirectPlay" {
		dst.playMethod = src.playMethod
	}
	if src.positionSec > dst.positionSec {
		dst.positionSec = src.positionSec
	}
	if dst.durationSec == 0 && src.durationSec > 0 {
		dst.durationSec = src.durationSec
	}
	title, sub := formatPlaybackFlowDisplay(dst)
	for fid, f := range src.flows {
		if f == nil {
			continue
		}
		dst.flows[fid] = f
		if p != nil {
			p.flowSessions[fid] = dst
		}
		if title != "" {
			f.SetMediaInfo(title, sub)
		}
	}
	clear(src.flows)
	if p != nil && src.key != "" && p.sessions[src.key] == src {
		delete(p.sessions, src.key)
	}
}

func (p *playbackTracker) findCompatibleSessionLocked(normIP, upstreamHost, itemID, clientName, userID, userName string, now time.Time) *playbackSessionEntry {
	var best *playbackSessionEntry
	for _, s := range p.sessions {
		if s == nil || s.stopped || now.Sub(s.lastSeenAt) > 15*time.Minute {
			continue
		}
		if normalizeTelemetryClientIP(s.clientIP) != normIP || !strings.EqualFold(s.upstreamHost, upstreamHost) || s.itemID != itemID {
			continue
		}
		if !playbackClientsCompatible(s.clientName, clientName) {
			continue
		}
		if !playbackUsersCompatible(s.userID, s.userName, userID, userName) {
			continue
		}
		if best == nil {
			best = s
			continue
		}
		sStrong := s.deviceID != ""
		bStrong := best.deviceID != ""
		if sStrong != bStrong {
			if sStrong {
				best = s
			}
			continue
		}
		sExactClient := clientName != "" && strings.EqualFold(s.clientName, clientName)
		bExactClient := clientName != "" && strings.EqualFold(best.clientName, clientName)
		if sExactClient != bExactClient {
			if sExactClient {
				best = s
			}
			continue
		}
		if s.lastSeenAt.After(best.lastSeenAt) {
			best = s
		}
	}
	return best
}

func (p *playbackTracker) getOrCreateSessionLocked(meta playbackRequestMeta, itemID string, now time.Time) *playbackSessionEntry {
	key := p.sessionKeyFor(meta, itemID)
	normIP := normalizeTelemetryClientIP(meta.ClientIP)
	resolvedUser := p.resolveUserNameLocked(meta.UpstreamHost, meta.UserID, meta.TokenHash, meta.DeviceID)
	sess := p.sessions[key]
	if sess != nil && (sess.stopped || now.Sub(sess.lastSeenAt) > 15*time.Minute) {
		p.detachSessionFlowsLocked(sess)
		delete(p.sessions, key)
		sess = nil
	}
	if strings.TrimSpace(meta.DeviceID) == "" {
		if best := p.findCompatibleSessionLocked(normIP, meta.UpstreamHost, itemID, meta.ClientName, meta.UserID, resolvedUser, now); best != nil && best != sess {
			if sess != nil {
				mergePlaybackSessionsLocked(p, best, sess)
			}
			sess = best
		}
	} else {
		var weakMatches []*playbackSessionEntry
		for _, s := range p.sessions {
			if s == nil || s == sess || s.stopped || now.Sub(s.lastSeenAt) > 15*time.Minute {
				continue
			}
			if s.deviceID != "" {
				continue
			}
			if normalizeTelemetryClientIP(s.clientIP) != normIP || !strings.EqualFold(s.upstreamHost, meta.UpstreamHost) || s.itemID != itemID {
				continue
			}
			if !playbackClientsCompatible(s.clientName, meta.ClientName) {
				continue
			}
			if !playbackUsersCompatible(s.userID, s.userName, meta.UserID, resolvedUser) {
				continue
			}
			weakMatches = append(weakMatches, s)
		}
		if len(weakMatches) > 0 {
			sort.Slice(weakMatches, func(i, j int) bool {
				return weakMatches[i].lastSeenAt.After(weakMatches[j].lastSeenAt)
			})
			if sess == nil {
				promoted := weakMatches[0]
				if promoted.key != "" && p.sessions[promoted.key] == promoted {
					delete(p.sessions, promoted.key)
				}
				promoted.key = key
				promoted.deviceID = truncateRunes(strings.TrimSpace(meta.DeviceID), 128)
				p.sessions[key] = promoted
				sess = promoted
				weakMatches = weakMatches[1:]
			}
			for _, weak := range weakMatches {
				mergePlaybackSessionsLocked(p, sess, weak)
			}
		}
	}
	if sess == nil {
		if len(p.sessions) >= playbackMaxActiveSessions {
			p.pruneLocked(now)
		}
		if len(p.sessions) >= playbackMaxActiveSessions {
			// Enforce hard upper bound by evicting the stalest session without active flows (or stalest overall).
			var oldestIdleKey, oldestAnyKey string
			var oldestIdleAt, oldestAnyAt time.Time
			for k, s := range p.sessions {
				if oldestAnyKey == "" || s.lastSeenAt.Before(oldestAnyAt) {
					oldestAnyKey, oldestAnyAt = k, s.lastSeenAt
				}
				if len(s.flows) == 0 && (oldestIdleKey == "" || s.lastSeenAt.Before(oldestIdleAt)) {
					oldestIdleKey, oldestIdleAt = k, s.lastSeenAt
				}
			}
			if oldestIdleKey != "" {
				p.detachSessionFlowsLocked(p.sessions[oldestIdleKey])
				delete(p.sessions, oldestIdleKey)
			} else if oldestAnyKey != "" {
				p.detachSessionFlowsLocked(p.sessions[oldestAnyKey])
				delete(p.sessions, oldestAnyKey)
			}
		}
		sess = &playbackSessionEntry{
			key:          key,
			clientIP:     normIP,
			clientName:   truncateRunes(strings.TrimSpace(meta.ClientName), 80),
			deviceName:   truncateRunes(strings.TrimSpace(meta.DeviceName), 80),
			deviceID:     truncateRunes(strings.TrimSpace(meta.DeviceID), 128),
			upstreamHost: strings.TrimSpace(meta.UpstreamHost),
			itemID:       strings.TrimSpace(itemID),
			flows:        make(map[string]*connectionFlow),
			startedAt:    now,
			lastSeenAt:   now,
		}
		p.sessions[key] = sess
	}
	sess.lastSeenAt = now
	if sess.clientName == "" && meta.ClientName != "" {
		sess.clientName = truncateRunes(strings.TrimSpace(meta.ClientName), 80)
	}
	if sess.deviceName == "" && meta.DeviceName != "" {
		sess.deviceName = truncateRunes(strings.TrimSpace(meta.DeviceName), 80)
	}
	if sess.userID == "" && meta.UserID != "" {
		sess.userID = meta.UserID
	}
	if user := p.resolveUserNameLocked(meta.UpstreamHost, meta.UserID, meta.TokenHash, meta.DeviceID); user != "" {
		sess.userName = user
	}
	if cached, ok := p.items[playbackCacheKey(meta.UpstreamHost, itemID)]; ok {
		applyItemToSession(sess, cached)
	}
	if sess.title == "" && itemID != "" {
		sess.title = "媒体 #" + truncateRunes(itemID, 24)
	}
	return sess
}

func playbackStreamBlockKey(clientIP, upstreamHost, itemID string) string {
	return fmt.Sprintf("stream|%s|%s|%s",
		normalizeTelemetryClientIP(clientIP),
		strings.ToLower(strings.TrimSpace(upstreamHost)),
		strings.TrimSpace(itemID),
	)
}

func (p *playbackTracker) isBlockedLocked(sessionKey, clientIP, upstreamHost, itemID string, now time.Time) bool {
	if p == nil || len(p.kicked) == 0 {
		return false
	}
	if sessionKey != "" {
		if exp, ok := p.kicked[sessionKey]; ok {
			if now.Before(exp) {
				return true
			}
			delete(p.kicked, sessionKey)
		}
	}
	if clientIP != "" && upstreamHost != "" && itemID != "" {
		sKey := playbackStreamBlockKey(clientIP, upstreamHost, itemID)
		if exp, ok := p.kicked[sKey]; ok {
			if now.Before(exp) {
				return true
			}
			delete(p.kicked, sKey)
		}
	}
	return false
}

func redirectExactKey(clientIP, host, escapedPath, rawQuery string) string {
	normPath := strings.TrimSpace(escapedPath)
	if normPath == "" {
		normPath = "/"
	}
	return fmt.Sprintf("exact|%s|%s|%s|%s",
		normalizeTelemetryClientIP(clientIP),
		strings.ToLower(strings.TrimSpace(host)),
		normPath,
		strings.TrimSpace(rawQuery),
	)
}

func redirectPathKey(clientIP, host, escapedPath string) string {
	normPath := strings.TrimSpace(escapedPath)
	if normPath == "" {
		normPath = "/"
	}
	return fmt.Sprintf("path|%s|%s|%s",
		normalizeTelemetryClientIP(clientIP),
		strings.ToLower(strings.TrimSpace(host)),
		normPath,
	)
}

func (p *playbackTracker) rememberRedirectLocked(meta playbackRequestMeta, dest *url.URL, itemID string, now time.Time) {
	if p == nil || dest == nil || strings.TrimSpace(dest.Host) == "" || strings.TrimSpace(meta.UpstreamHost) == "" || strings.TrimSpace(itemID) == "" {
		return
	}
	if len(p.redirects) >= playbackRedirectCacheLimit {
		for k, b := range p.redirects {
			if !now.Before(b.expiresAt) {
				delete(p.redirects, k)
			}
		}
		if len(p.redirects) >= playbackRedirectCacheLimit {
			type rPair struct {
				k string
				t time.Time
			}
			all := make([]rPair, 0, len(p.redirects))
			for k, b := range p.redirects {
				all = append(all, rPair{k: k, t: b.expiresAt})
			}
			sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
			evict := len(all) / 4
			if evict == 0 {
				evict = 1
			}
			for i := 0; i < evict && i < len(all); i++ {
				delete(p.redirects, all[i].k)
			}
		}
	}
	binding := playbackRedirectBinding{
		clientIP:     normalizeTelemetryClientIP(meta.ClientIP),
		upstreamHost: strings.TrimSpace(meta.UpstreamHost),
		itemID:       strings.TrimSpace(itemID),
		deviceID:     strings.TrimSpace(meta.DeviceID),
		deviceName:   strings.TrimSpace(meta.DeviceName),
		clientName:   strings.TrimSpace(meta.ClientName),
		token:        meta.Token,
		tokenHash:    meta.TokenHash,
		userID:       strings.TrimSpace(meta.UserID),
		expiresAt:    now.Add(playbackRedirectTTL),
	}
	destPath := dest.EscapedPath()
	p.redirects[redirectExactKey(meta.ClientIP, dest.Host, destPath, dest.RawQuery)] = binding
	if destPath != "" && destPath != "/" {
		p.redirects[redirectPathKey(meta.ClientIP, dest.Host, destPath)] = binding
	}
}

func (p *playbackTracker) lookupRedirectLocked(clientIP, host, escapedPath, rawQuery string, now time.Time) (playbackRedirectBinding, bool) {
	if p == nil || len(p.redirects) == 0 || host == "" {
		return playbackRedirectBinding{}, false
	}
	ek := redirectExactKey(clientIP, host, escapedPath, rawQuery)
	if b, ok := p.redirects[ek]; ok {
		if now.Before(b.expiresAt) {
			return b, true
		}
		delete(p.redirects, ek)
	}
	if escapedPath != "" && escapedPath != "/" {
		pk := redirectPathKey(clientIP, host, escapedPath)
		if b, ok := p.redirects[pk]; ok {
			if now.Before(b.expiresAt) {
				return b, true
			}
			delete(p.redirects, pk)
		}
	}
	return playbackRedirectBinding{}, false
}

func extractStreamQueryIDs(rawQuery string) (playSessionID, mediaSourceID string) {
	if strings.TrimSpace(rawQuery) == "" {
		return "", ""
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil || len(q) == 0 {
		return "", ""
	}
	for k, vals := range q {
		if len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		if v == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "playsessionid", "play_session_id":
			if playSessionID == "" {
				playSessionID = v
			}
		case "mediasourceid", "media_source_id":
			if mediaSourceID == "" {
				mediaSourceID = v
			}
		}
	}
	return playSessionID, mediaSourceID
}

func (p *playbackTracker) rememberItemAliasLocked(host, aliasID, canonicalID string) {
	host = strings.TrimSpace(host)
	aliasID = strings.TrimSpace(aliasID)
	canonicalID = strings.TrimSpace(canonicalID)
	if p == nil || host == "" || aliasID == "" || canonicalID == "" || aliasID == canonicalID {
		return
	}
	// Resolve canonicalID root up to 4 hops and refuse any write that creates a 2-cycle (A <-> B).
	root := canonicalID
	for step := 0; step < 4; step++ {
		next := p.itemAliases[playbackCacheKey(host, root)]
		if next == "" || next == root {
			break
		}
		if next == aliasID {
			return
		}
		root = next
	}
	if len(p.itemAliases) >= playbackMetadataCacheLimit {
		clear(p.itemAliases)
	}
	p.itemAliases[playbackCacheKey(host, aliasID)] = root
}

func (p *playbackTracker) AliasItemIDs(upstreamHost, canonicalID string) []string {
	if p == nil || strings.TrimSpace(upstreamHost) == "" || strings.TrimSpace(canonicalID) == "" {
		return nil
	}
	prefix := strings.ToLower(strings.TrimSpace(upstreamHost)) + "|"
	canonicalID = strings.TrimSpace(canonicalID)
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []string
	for k, v := range p.itemAliases {
		if strings.HasPrefix(k, prefix) && v == canonicalID {
			out = append(out, strings.TrimPrefix(k, prefix))
		}
	}
	return out
}

func (p *playbackTracker) canonicalItemIDLocked(host, rawID, playSessionID, mediaSourceID string) string {
	host = strings.TrimSpace(host)
	rawID = strings.TrimSpace(rawID)
	playSessionID = strings.TrimSpace(playSessionID)
	mediaSourceID = strings.TrimSpace(mediaSourceID)
	if p == nil || host == "" {
		return rawID
	}
	if playSessionID != "" {
		if mapped := p.playToItem[playbackCacheKey(host, playSessionID)]; mapped != "" {
			if rawID != "" && rawID != mapped {
				p.rememberItemAliasLocked(host, rawID, mapped)
			}
			return mapped
		}
	}
	if mediaSourceID != "" {
		if mapped := p.sourceToItem[playbackCacheKey(host, mediaSourceID)]; mapped != "" {
			if rawID != "" && rawID != mapped {
				p.rememberItemAliasLocked(host, rawID, mapped)
			}
			return mapped
		}
	}
	if rawID != "" {
		if mapped := p.itemAliases[playbackCacheKey(host, rawID)]; mapped != "" {
			return mapped
		}
		if mapped := p.sourceToItem[playbackCacheKey(host, rawID)]; mapped != "" {
			return mapped
		}
	}
	return rawID
}

func (p *playbackTracker) indexMediaSourcesLocked(meta playbackRequestMeta, canonicalItemID string, sources []any, registerRedirects bool) {
	canonicalItemID = strings.TrimSpace(canonicalItemID)
	if p == nil || meta.UpstreamHost == "" || canonicalItemID == "" || len(sources) == 0 {
		return
	}
	now := time.Now()
	for _, rawSrc := range sources {
		src, ok := rawSrc.(map[string]any)
		if !ok {
			continue
		}
		if srcID := jsonStringField(src, "Id"); srcID != "" {
			if len(p.sourceToItem) >= playbackMetadataCacheLimit {
				clear(p.sourceToItem)
			}
			p.sourceToItem[playbackCacheKey(meta.UpstreamHost, srcID)] = canonicalItemID
			if srcID != canonicalItemID {
				p.rememberItemAliasLocked(meta.UpstreamHost, srcID, canonicalItemID)
			}
		}
		if srcItemID := jsonStringField(src, "ItemId"); srcItemID != "" && srcItemID != canonicalItemID {
			p.rememberItemAliasLocked(meta.UpstreamHost, srcItemID, canonicalItemID)
		}
		for _, field := range []string{"DirectStreamUrl", "TranscodingUrl", "Path"} {
			rawURL := jsonStringField(src, field)
			if rawURL == "" {
				continue
			}
			parsed, err := url.Parse(rawURL)
			if err != nil || parsed == nil {
				continue
			}
			if streamID, isStream, _ := extractEmbyItemIDFromPath(parsed.Path); isStream && streamID != "" && streamID != canonicalItemID {
				p.rememberItemAliasLocked(meta.UpstreamHost, streamID, canonicalItemID)
			}
			psID, msID := extractStreamQueryIDs(parsed.RawQuery)
			if psID != "" {
				if len(p.playToItem) >= playbackMetadataCacheLimit {
					clear(p.playToItem)
				}
				p.playToItem[playbackCacheKey(meta.UpstreamHost, psID)] = canonicalItemID
			}
			if msID != "" {
				if len(p.sourceToItem) >= playbackMetadataCacheLimit {
					clear(p.sourceToItem)
				}
				p.sourceToItem[playbackCacheKey(meta.UpstreamHost, msID)] = canonicalItemID
			}
			if registerRedirects && hasHTTPPrefix(rawURL) && parsed.Host != "" {
				p.rememberRedirectLocked(meta, parsed, canonicalItemID, now)
			}
		}
	}
}

func (p *playbackTracker) resolveStreamTargetLocked(meta playbackRequestMeta, now time.Time) (upstreamHost, itemID string, binding *playbackRedirectBinding, ok bool) {
	psID, msID := extractStreamQueryIDs(meta.RawQuery)
	if id, isStream, _ := extractEmbyItemIDFromPath(meta.Path); isStream && id != "" {
		return meta.UpstreamHost, p.canonicalItemIDLocked(meta.UpstreamHost, id, psID, msID), nil, true
	}
	if b, found := p.lookupRedirectLocked(meta.ClientIP, meta.UpstreamHost, meta.Path, meta.RawQuery, now); found {
		return b.upstreamHost, p.canonicalItemIDLocked(b.upstreamHost, b.itemID, psID, msID), &b, true
	}
	return "", "", nil, false
}

// ObserveStreamRedirect binds an HTTP 30x Location target (or HLS / PlaybackInfo external URL)
// back to the originating Emby server and ItemID so redirected storage streams stay linked.
func (p *playbackTracker) ObserveStreamRedirect(meta playbackRequestMeta, dest *url.URL) {
	if p == nil || dest == nil || strings.TrimSpace(dest.Host) == "" || strings.TrimSpace(meta.UpstreamHost) == "" {
		return
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	origHost, itemID, binding, ok := p.resolveStreamTargetLocked(meta, now)
	if !ok || origHost == "" || itemID == "" {
		return
	}
	origMeta := meta
	origMeta.UpstreamHost = origHost
	if binding != nil {
		if origMeta.ClientIP == "" {
			origMeta.ClientIP = binding.clientIP
		}
		if origMeta.DeviceID == "" {
			origMeta.DeviceID = binding.deviceID
		}
		if origMeta.DeviceName == "" {
			origMeta.DeviceName = binding.deviceName
		}
		if origMeta.ClientName == "" {
			origMeta.ClientName = binding.clientName
		}
		if origMeta.Token == "" {
			origMeta.Token = binding.token
		}
		if origMeta.TokenHash == "" {
			origMeta.TokenHash = binding.tokenHash
		}
		if origMeta.UserID == "" {
			origMeta.UserID = binding.userID
		}
	}
	p.rememberRedirectLocked(origMeta, dest, itemID, now)
}

func (p *playbackTracker) IsRequestBlocked(clientIP, upstreamHost, reqPath, rawQuery, deviceID, clientName string, now time.Time) bool {
	if p == nil {
		return false
	}
	meta := playbackRequestMeta{
		ClientIP:     clientIP,
		UpstreamHost: upstreamHost,
		Path:         reqPath,
		RawQuery:     rawQuery,
		DeviceID:     deviceID,
		ClientName:   clientName,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	origHost, itemID, binding, ok := p.resolveStreamTargetLocked(meta, now)
	if !ok || itemID == "" {
		return false
	}
	effMeta := playbackRequestMeta{
		ClientIP:     clientIP,
		UpstreamHost: origHost,
		DeviceID:     deviceID,
		ClientName:   clientName,
	}
	if binding != nil {
		if effMeta.DeviceID == "" {
			effMeta.DeviceID = binding.deviceID
		}
		if effMeta.ClientName == "" {
			effMeta.ClientName = binding.clientName
		}
	}
	key := p.sessionKeyFor(effMeta, itemID)
	return p.isBlockedLocked(key, clientIP, origHost, itemID, now)
}

func (p *playbackTracker) TerminateSession(sessionKey string, blockDuration time.Duration) (canceled int, clientIP, upstreamHost, itemID string) {
	sessionKey = strings.TrimSpace(sessionKey)
	if p == nil || sessionKey == "" {
		return 0, "", "", ""
	}
	if blockDuration <= 0 {
		blockDuration = playbackKickBlockTTL
	}
	now := time.Now()
	exp := now.Add(blockDuration)

	p.mu.Lock()
	sess := p.sessions[sessionKey]
	if sess != nil {
		clientIP = sess.clientIP
		upstreamHost = sess.upstreamHost
		itemID = sess.itemID
	}
	if parts := strings.SplitN(sessionKey, "|", 4); len(parts) == 4 {
		if clientIP == "" {
			clientIP = normalizeTelemetryClientIP(parts[0])
		}
		if upstreamHost == "" {
			upstreamHost = strings.TrimSpace(parts[2])
		}
		if itemID == "" {
			itemID = strings.TrimSpace(parts[3])
		}
	}
	cancels := make([]context.CancelFunc, 0, 4)
	for k, s := range p.sessions {
		sameKey := k == sessionKey
		sameStream := clientIP != "" && upstreamHost != "" && itemID != "" &&
			normalizeTelemetryClientIP(s.clientIP) == normalizeTelemetryClientIP(clientIP) &&
			strings.EqualFold(s.upstreamHost, upstreamHost) &&
			s.itemID == itemID
		if !sameKey && !sameStream {
			continue
		}
		for fid, f := range s.flows {
			delete(p.flowSessions, fid)
			if f != nil && f.cancel != nil {
				cancels = append(cancels, f.cancel)
			}
		}
		p.kicked[k] = exp
		delete(p.sessions, k)
	}
	p.kicked[sessionKey] = exp
	if clientIP != "" && upstreamHost != "" && itemID != "" {
		p.kicked[playbackStreamBlockKey(clientIP, upstreamHost, itemID)] = exp
	}
	p.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	return len(cancels), clientIP, upstreamHost, itemID
}

func (p *playbackTracker) pruneLocked(now time.Time) {
	for k, exp := range p.kicked {
		if !now.Before(exp) {
			delete(p.kicked, k)
		}
	}
	for k, b := range p.redirects {
		if !now.Before(b.expiresAt) {
			delete(p.redirects, k)
		}
	}
	for key, sess := range p.sessions {
		if len(sess.flows) > 0 {
			continue
		}
		ttl := playbackSessionActiveTTL
		if sess.stopped {
			ttl = 3 * time.Second
		}
		if now.Sub(sess.lastSeenAt) > ttl {
			p.detachSessionFlowsLocked(sess)
			delete(p.sessions, key)
		}
	}
}

// ObserveStreamStart links an active media stream flow (/Videos/{id}/..., /Audio/{id}/..., /Download, or 302-redirected CDN target)
// to a live playback session and returns true if metadata is still missing and eligible for async lookup.
func (p *playbackTracker) ObserveStreamStart(meta playbackRequestMeta) (itemID string, needsLookup bool, blocked bool) {
	if p == nil {
		return "", false, false
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()

	origHost, extractedID, binding, ok := p.resolveStreamTargetLocked(meta, now)
	if !ok || extractedID == "" {
		return "", false, false
	}
	effMeta := meta
	effMeta.UpstreamHost = origHost
	if binding != nil {
		if effMeta.ClientIP == "" {
			effMeta.ClientIP = binding.clientIP
		}
		if effMeta.DeviceID == "" {
			effMeta.DeviceID = binding.deviceID
		}
		if effMeta.DeviceName == "" {
			effMeta.DeviceName = binding.deviceName
		}
		if effMeta.ClientName == "" {
			effMeta.ClientName = binding.clientName
		}
		if effMeta.Token == "" {
			effMeta.Token = binding.token
		}
		if effMeta.TokenHash == "" {
			effMeta.TokenHash = binding.tokenHash
		}
		if effMeta.UserID == "" {
			effMeta.UserID = binding.userID
		}
	}

	psID, msID := extractStreamQueryIDs(meta.RawQuery)
	if effMeta.DeviceID != "" {
		if _, hasCached := p.items[playbackCacheKey(effMeta.UpstreamHost, extractedID)]; !hasCached {
			normIP := normalizeTelemetryClientIP(effMeta.ClientIP)
			var reverseCands []*playbackSessionEntry
			for _, s := range p.sessions {
				if s == nil || s.stopped || s.itemID == "" || s.itemID == extractedID {
					continue
				}
				if normalizeTelemetryClientIP(s.clientIP) != normIP || s.deviceID != effMeta.DeviceID || !strings.EqualFold(s.upstreamHost, effMeta.UpstreamHost) {
					continue
				}
				if len(s.flows) == 0 && s.closedBytesOut == 0 && s.title != "" && !strings.HasPrefix(s.title, "媒体 #") && now.Sub(s.lastSeenAt) <= 30*time.Second {
					reverseCands = append(reverseCands, s)
				}
			}
			if len(reverseCands) == 1 {
				// Bind this session locally without polluting host-global p.itemAliases.
				extractedID = reverseCands[0].itemID
			}
		}
	}

	if p.isBlockedLocked(p.sessionKeyFor(effMeta, extractedID), effMeta.ClientIP, effMeta.UpstreamHost, extractedID, now) {
		return extractedID, false, true
	}
	sess := p.getOrCreateSessionLocked(effMeta, extractedID, now)
	if sess.playSessionID == "" && psID != "" {
		sess.playSessionID = psID
	}
	if sess.mediaSourceID == "" && msID != "" {
		sess.mediaSourceID = msID
	}
	if meta.Flow != nil {
		sess.flows[meta.Flow.id] = meta.Flow
		p.flowSessions[meta.Flow.id] = sess
		title, sub := formatPlaybackFlowDisplay(sess)
		meta.Flow.SetMediaInfo(title, sub)
	}
	if sess.playMethod == "" {
		lower := strings.ToLower(meta.Path)
		switch {
		case strings.Contains(lower, ".m3u8"), strings.Contains(lower, "/hls"), strings.Contains(lower, "main.m3u8"):
			sess.playMethod = "Transcode"
		default:
			sess.playMethod = "DirectPlay"
		}
	}

	// Never trigger async metadata lookup against redirected CDN DialAddresses/UpstreamHost (binding != nil).
	cached, hasCached := p.items[playbackCacheKey(effMeta.UpstreamHost, extractedID)]
	rich := hasCached && cached.Title != "" && cached.MediaType != "" && !cached.FromFilename
	if binding == nil && !rich && effMeta.Token != "" && len(effMeta.DialAddresses) > 0 {
		lKey := playbackCacheKey(effMeta.UpstreamHost, extractedID)
		if last, seen := p.lookups[lKey]; !seen || now.Sub(last) > 5*time.Minute {
			if len(p.lookups) > 2048 {
				clear(p.lookups)
			}
			p.lookups[lKey] = now
			needsLookup = true
		}
	}
	return extractedID, needsLookup, false
}

// ObserveStreamEnd detaches a finished stream flow and accumulates its transferred bytes into the session.
func (p *playbackTracker) ObserveStreamEnd(meta playbackRequestMeta, bytesOut int64) {
	if p == nil || meta.Flow == nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	sess := p.flowSessions[meta.Flow.id]
	delete(p.flowSessions, meta.Flow.id)
	if sess == nil {
		if origHost, extractedID, binding, ok := p.resolveStreamTargetLocked(meta, now); ok && extractedID != "" {
			effMeta := meta
			effMeta.UpstreamHost = origHost
			if binding != nil && effMeta.DeviceID == "" {
				effMeta.DeviceID = binding.deviceID
			}
			if binding != nil && effMeta.ClientName == "" {
				effMeta.ClientName = binding.clientName
			}
			sess = p.sessions[p.sessionKeyFor(effMeta, extractedID)]
		}
	}
	if sess != nil {
		if _, ok := sess.flows[meta.Flow.id]; ok {
			delete(sess.flows, meta.Flow.id)
			if bytesOut > 0 {
				sess.closedBytesOut += bytesOut
			}
			sess.lastSeenAt = now
		}
	}
}

// ObserveStreamResponseHeaders parses Content-Disposition filenames as a zero-cost title fallback.
func (p *playbackTracker) ObserveStreamResponseHeaders(meta playbackRequestMeta, headers http.Header) {
	if p == nil || headers == nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	var origHost, extractedID string
	if meta.Flow != nil {
		if sess := p.flowSessions[meta.Flow.id]; sess != nil {
			origHost = sess.upstreamHost
			extractedID = sess.itemID
		}
	}
	if extractedID == "" {
		if resolvedHost, resolvedID, _, ok := p.resolveStreamTargetLocked(meta, now); ok {
			origHost = resolvedHost
			extractedID = resolvedID
		}
	}
	p.mu.Unlock()
	if extractedID == "" || origHost == "" {
		return
	}
	disp := headers.Get("Content-Disposition")
	if disp == "" {
		return
	}
	m := reDispositionFilename.FindStringSubmatch(disp)
	if len(m) != 2 {
		return
	}
	rawName := strings.Trim(m[1], `" `)
	if decoded, err := url.QueryUnescape(rawName); err == nil && decoded != "" {
		rawName = decoded
	}
	item := parseFilenameFallbackItem(extractedID, rawName)
	if item.Title == "" {
		return
	}
	p.mu.Lock()
	p.upsertItemLocked(origHost, item)
	p.mu.Unlock()
}

func (p *playbackTracker) findAliasStreamSessionsLocked(meta playbackRequestMeta, canonicalID, playSessionID, mediaSourceID, resolvedUser string, targetHasTraffic, allowPlaceholder bool, now time.Time) []*playbackSessionEntry {
	if p == nil || canonicalID == "" || meta.UpstreamHost == "" {
		return nil
	}
	normIP := normalizeTelemetryClientIP(meta.ClientIP)
	var ruleA []*playbackSessionEntry
	var ruleB []*playbackSessionEntry
	for _, s := range p.sessions {
		if s == nil || s.stopped || s.itemID == canonicalID {
			continue
		}
		if normalizeTelemetryClientIP(s.clientIP) != normIP || !strings.EqualFold(s.upstreamHost, meta.UpstreamHost) {
			continue
		}
		if !playbackClientsCompatible(s.clientName, meta.ClientName) {
			continue
		}
		if !playbackUsersCompatible(s.userID, s.userName, meta.UserID, resolvedUser) {
			continue
		}
		deviceCompatible := meta.DeviceID == "" || s.deviceID == "" || s.deviceID == meta.DeviceID
		if deviceCompatible && ((playSessionID != "" && s.playSessionID == playSessionID) ||
			(mediaSourceID != "" && (s.mediaSourceID == mediaSourceID || s.itemID == mediaSourceID))) {
			ruleA = append(ruleA, s)
			continue
		}
		if allowPlaceholder && !targetHasTraffic && meta.DeviceID != "" && s.deviceID == meta.DeviceID &&
			(s.title == "" || strings.HasPrefix(s.title, "媒体 #")) && s.mediaType == "" && s.positionSec == 0 &&
			(len(s.flows) > 0 || s.closedBytesOut > 0) && now.Sub(s.lastSeenAt) <= 45*time.Second {
			cItem, hasC := p.items[playbackCacheKey(meta.UpstreamHost, s.itemID)]
			if !hasC || (cItem.Title == "" && cItem.MediaType == "") {
				ruleB = append(ruleB, s)
			}
		}
	}
	if len(ruleA) > 0 {
		return ruleA
	}
	if len(ruleB) == 1 {
		return ruleB
	}
	return nil
}

// ObservePlayingReport parses Emby/Jellyfin POST /Sessions/Playing(|/Progress|/Stopped) request bodies.
func (p *playbackTracker) ObservePlayingReport(meta playbackRequestMeta, body []byte) (itemID string, needsLookup bool) {
	if p == nil || len(body) == 0 {
		return "", false
	}
	action, ok := isEmbyPlayingReportPath(meta.Path)
	if !ok {
		return "", false
	}
	var payload struct {
		ItemID        json.RawMessage `json:"ItemId"`
		MediaSourceID string          `json:"MediaSourceId"`
		PlaySessionID string          `json:"PlaySessionId"`
		PositionTicks *int64          `json:"PositionTicks"`
		IsPaused      bool            `json:"IsPaused"`
		PlayMethod    string          `json:"PlayMethod"`
		Item          map[string]any  `json:"Item"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", false
	}
	rawID := rawJSONToString(payload.ItemID)
	var parsedItem cachedMediaItem
	var hasParsedItem bool
	if payload.Item != nil {
		parsedItem, hasParsedItem = parseEmbyItemMap(payload.Item)
	}
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	id := rawID
	if id == "" && hasParsedItem {
		id = parsedItem.ItemID
	}
	if id == "" && payload.MediaSourceID != "" {
		id = p.sourceToItem[playbackCacheKey(meta.UpstreamHost, payload.MediaSourceID)]
	}
	if id == "" && payload.PlaySessionID != "" {
		id = p.playToItem[playbackCacheKey(meta.UpstreamHost, payload.PlaySessionID)]
	}
	if id == "" {
		return "", false
	}
	canonID := p.canonicalItemIDLocked(meta.UpstreamHost, id, payload.PlaySessionID, payload.MediaSourceID)
	if canonID != "" {
		id = canonID
	}

	if action != "stopped" {
		if (rawID != "" && p.isBlockedLocked(p.sessionKeyFor(meta, rawID), meta.ClientIP, meta.UpstreamHost, rawID, now)) ||
			p.isBlockedLocked(p.sessionKeyFor(meta, id), meta.ClientIP, meta.UpstreamHost, id, now) {
			return id, false
		}
	}

	if hasParsedItem {
		parsedItem.ItemID = id
		p.upsertItemLocked(meta.UpstreamHost, parsedItem)
	}
	if payload.MediaSourceID != "" {
		if len(p.sourceToItem) >= playbackMetadataCacheLimit {
			clear(p.sourceToItem)
		}
		p.sourceToItem[playbackCacheKey(meta.UpstreamHost, payload.MediaSourceID)] = id
		if payload.MediaSourceID != id {
			p.rememberItemAliasLocked(meta.UpstreamHost, payload.MediaSourceID, id)
		}
	}
	if payload.PlaySessionID != "" {
		if len(p.playToItem) >= playbackMetadataCacheLimit {
			clear(p.playToItem)
		}
		p.playToItem[playbackCacheKey(meta.UpstreamHost, payload.PlaySessionID)] = id
	}
	resolvedUser := p.resolveUserNameLocked(meta.UpstreamHost, meta.UserID, meta.TokenHash, meta.DeviceID)

	if action == "stopped" {
		normIP := normalizeTelemetryClientIP(meta.ClientIP)
		key := p.sessionKeyFor(meta, id)
		if sess := p.sessions[key]; sess != nil {
			if payload.PositionTicks != nil && *payload.PositionTicks > 0 {
				sess.positionSec = *payload.PositionTicks / 10_000_000
			}
			sess.paused = false
			sess.stopped = true
			sess.lastSeenAt = now
		}
		for _, s := range p.sessions {
			if s == nil || s.deviceID != "" || len(s.flows) > 0 {
				continue
			}
			if normalizeTelemetryClientIP(s.clientIP) == normIP && strings.EqualFold(s.upstreamHost, meta.UpstreamHost) && s.itemID == id && playbackClientsCompatible(s.clientName, meta.ClientName) && playbackUsersCompatible(s.userID, s.userName, meta.UserID, resolvedUser) {
				s.paused = false
				s.stopped = true
				s.lastSeenAt = now
			}
		}
		for _, aliasSess := range p.findAliasStreamSessionsLocked(meta, id, payload.PlaySessionID, payload.MediaSourceID, resolvedUser, true, false, now) {
			if len(aliasSess.flows) == 0 {
				aliasSess.paused = false
				aliasSess.stopped = true
				aliasSess.lastSeenAt = now
			}
		}
		return id, false
	}

	sess := p.getOrCreateSessionLocked(meta, id, now)
	if payload.PositionTicks != nil && *payload.PositionTicks >= 0 {
		sess.positionSec = *payload.PositionTicks / 10_000_000
	}
	sess.paused = payload.IsPaused
	if pm := strings.TrimSpace(payload.PlayMethod); pm != "" {
		sess.playMethod = pm
	}
	if payload.MediaSourceID != "" {
		sess.mediaSourceID = payload.MediaSourceID
	}
	if payload.PlaySessionID != "" {
		sess.playSessionID = payload.PlaySessionID
	}

	targetHasTraffic := len(sess.flows) > 0 || sess.closedBytesOut > 0
	for _, aliasSess := range p.findAliasStreamSessionsLocked(meta, id, payload.PlaySessionID, payload.MediaSourceID, resolvedUser, targetHasTraffic, true, now) {
		mergePlaybackSessionsLocked(p, sess, aliasSess)
	}

	cached, hasCached := p.items[playbackCacheKey(meta.UpstreamHost, id)]
	rich := hasCached && cached.Title != "" && cached.MediaType != "" && !cached.FromFilename
	if !rich && meta.Token != "" {
		lKey := playbackCacheKey(meta.UpstreamHost, id)
		if last, seen := p.lookups[lKey]; !seen || now.Sub(last) > 5*time.Minute {
			if len(p.lookups) >= 2048 {
				clear(p.lookups)
			}
			p.lookups[lKey] = now
			needsLookup = true
		}
	}
	return id, needsLookup
}

// ObserveJSONResponse passively extracts user names, media item metadata, and PlaybackInfo
// from Emby/Jellyfin JSON payloads already parsed during response rewriting.
func (p *playbackTracker) ObserveJSONResponse(meta playbackRequestMeta, value any) {
	if p == nil || value == nil || meta.UpstreamHost == "" {
		return
	}
	root, ok := value.(map[string]any)
	if !ok {
		if arr, isArr := value.([]any); isArr {
			p.mu.Lock()
			for _, elem := range arr {
				if m, ok := elem.(map[string]any); ok {
					if item, ok := parseEmbyItemMap(m); ok {
						p.upsertItemLocked(meta.UpstreamHost, item)
					}
				}
			}
			p.mu.Unlock()
		}
		return
	}

	lowerPath := strings.ToLower(meta.Path)
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. User Authentication / Profile responses
	if userObj, hasUser := root["User"].(map[string]any); hasUser {
		uid := jsonStringField(userObj, "Id")
		uname := jsonStringField(userObj, "Name")
		accessTok := jsonStringField(root, "AccessToken")
		tokHash := meta.TokenHash
		if accessTok != "" {
			sum := sha256.Sum256([]byte(accessTok))
			tokHash = hex.EncodeToString(sum[:12])
		}
		p.rememberUserLocked(meta.UpstreamHost, uid, uname, tokHash, meta.DeviceID)
	} else if strings.Contains(lowerPath, "/users/") && !strings.Contains(lowerPath, "/items") {
		if _, hasPolicy := root["Policy"]; hasPolicy || root["HasPassword"] != nil || root["Configuration"] != nil {
			p.rememberUserLocked(meta.UpstreamHost, jsonStringField(root, "Id"), jsonStringField(root, "Name"), meta.TokenHash, meta.DeviceID)
		}
	}

	// 2. PlaybackInfo response (/Items/{ItemId}/PlaybackInfo)
	if itemID, _, isPB := extractEmbyItemIDFromPath(meta.Path); isPB && itemID != "" {
		playSessionID := jsonStringField(root, "PlaySessionId")
		if playSessionID != "" {
			if len(p.playToItem) >= playbackMetadataCacheLimit {
				clear(p.playToItem)
			}
			p.playToItem[playbackCacheKey(meta.UpstreamHost, playSessionID)] = itemID
		}
		if sources, ok := root["MediaSources"].([]any); ok && len(sources) > 0 {
			if src, ok := sources[0].(map[string]any); ok {
				item := parseMediaSourceFallbackItem(itemID, src)
				p.upsertItemLocked(meta.UpstreamHost, item)
			}
			p.indexMediaSourcesLocked(meta, itemID, sources, true)
		}
		return
	}

	// 3. Collection responses (Items[], SearchHints[])
	for _, listKey := range []string{"Items", "SearchHints"} {
		if arr, ok := root[listKey].([]any); ok {
			limit := min(len(arr), 120)
			for i := 0; i < limit; i++ {
				if m, ok := arr[i].(map[string]any); ok {
					if item, ok := parseEmbyItemMap(m); ok {
						p.upsertItemLocked(meta.UpstreamHost, item)
						if sources, ok := m["MediaSources"].([]any); ok && len(sources) > 0 {
							p.indexMediaSourcesLocked(meta, item.ItemID, sources, false)
						}
					}
				}
			}
			return
		}
	}

	// 4. Single Item detail response (/Users/{uid}/Items/{id} or /Items/{id})
	if item, ok := parseEmbyItemMap(root); ok {
		p.upsertItemLocked(meta.UpstreamHost, item)
		if sources, ok := root["MediaSources"].([]any); ok && len(sources) > 0 {
			p.indexMediaSourcesLocked(meta, item.ItemID, sources, false)
		}
	}
}

// FetchItemMetadataAsync performs a single SSRF-pinned background lookup to resolve
// exact media metadata for cold-start direct streams (e.g. Infuse cached library).
func (p *playbackTracker) FetchItemMetadataAsync(meta playbackRequestMeta, itemID string) {
	if p == nil || itemID == "" || meta.Token == "" || len(meta.DialAddresses) == 0 || meta.UpstreamHost == "" {
		return
	}
	if p.fetchSem != nil {
		select {
		case p.fetchSem <- struct{}{}:
		default:
			return
		}
	}
	go func() {
		if p.fetchSem != nil {
			defer func() { <-p.fetchSem }()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
		defer cancel()
		scheme := meta.Scheme
		if scheme != "http" && scheme != "https" {
			scheme = "https"
		}
		prefix := ""
		if strings.HasPrefix(strings.ToLower(meta.Path), "/emby/") {
			prefix = "/emby"
		}
		var endpoint string
		if meta.UserID != "" {
			endpoint = fmt.Sprintf("%s://%s%s/Users/%s/Items/%s", scheme, meta.UpstreamHost, prefix, url.PathEscape(meta.UserID), url.PathEscape(itemID))
		} else {
			endpoint = fmt.Sprintf("%s://%s%s/Items?Ids=%s&Fields=ProductionYear,MediaSources", scheme, meta.UpstreamHost, prefix, url.QueryEscape(itemID))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return
		}
		req.Header.Set("X-Emby-Token", meta.Token)
		req.Header.Set("X-MediaBrowser-Token", meta.Token)
		req.Header.Set("Accept", "application/json")
		dialer := &net.Dialer{Timeout: 2500 * time.Millisecond}
		transport := &http.Transport{
			Proxy: nil,
			DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
				var lastErr error
				for _, addr := range meta.DialAddresses {
					conn, dErr := dialer.DialContext(c, network, addr)
					if dErr == nil {
						return conn, nil
					}
					lastErr = dErr
				}
				return nil, lastErr
			},
			DisableKeepAlives: true,
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{
			Transport: transport,
			Timeout:   3500 * time.Millisecond,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		if err != nil || len(raw) == 0 {
			return
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var decoded any
		if err := dec.Decode(&decoded); err != nil {
			return
		}
		p.ObserveJSONResponse(meta, decoded)
	}()
}

// Snapshot returns currently active playback sessions sorted by live download speed then recency.
func (p *playbackTracker) Snapshot() []playbackSessionSnapshot {
	if p == nil {
		return []playbackSessionSnapshot{}
	}
	now := time.Now()
	p.mu.Lock()
	p.pruneLocked(now)
	out := make([]playbackSessionSnapshot, 0, len(p.sessions))
	for _, sess := range p.sessions {
		if sess.stopped && len(sess.flows) == 0 {
			continue
		}
		var dlBPS int64
		bytesOut := sess.closedBytesOut
		var primaryFlowID string
		var topFlowBPS int64 = -1
		for _, f := range sess.flows {
			bps := f.downloadRate.Load()
			dlBPS += bps
			bytesOut += f.downloadTotal.Load()
			if bps > topFlowBPS {
				topFlowBPS = bps
				primaryFlowID = f.id
			}
		}
		pct := 0
		if sess.durationSec > 0 && sess.positionSec > 0 {
			pct = int(min(100, (sess.positionSec*100)/sess.durationSec))
		}
		out = append(out, playbackSessionSnapshot{
			SessionKey:     sess.key,
			UserName:       sess.userName,
			ClientIP:       sess.clientIP,
			ClientName:     sess.clientName,
			DeviceName:     sess.deviceName,
			DeviceID:       sess.deviceID,
			UpstreamHost:   sess.upstreamHost,
			ItemID:         sess.itemID,
			MediaType:      sess.mediaType,
			Title:          sess.title,
			SeriesName:     sess.seriesName,
			SeasonNumber:   sess.seasonNumber,
			EpisodeNumber:  sess.episodeNumber,
			ProductionYear: sess.productionYear,
			VideoQuality:   sess.videoQuality,
			Container:      sess.container,
			PlayMethod:     sess.playMethod,
			PositionSec:    sess.positionSec,
			DurationSec:    sess.durationSec,
			ProgressPct:    pct,
			Paused:         sess.paused,
			DownloadBPS:    dlBPS,
			BytesOut:       bytesOut,
			ActiveStreams:  len(sess.flows),
			FlowID:         primaryFlowID,
			StartedAt:      sess.startedAt.Unix(),
			LastSeenAt:     sess.lastSeenAt.Unix(),
		})
	}
	p.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].DownloadBPS != out[j].DownloadBPS {
			return out[i].DownloadBPS > out[j].DownloadBPS
		}
		return out[i].LastSeenAt > out[j].LastSeenAt
	})
	return out
}

func parseEmbyItemMap(m map[string]any) (cachedMediaItem, bool) {
	id := jsonStringField(m, "Id")
	if id == "" {
		id = jsonStringField(m, "ItemId")
	}
	name := jsonStringField(m, "Name")
	mediaType := jsonStringField(m, "Type")
	if id == "" || name == "" {
		return cachedMediaItem{}, false
	}
	switch mediaType {
	case "Episode", "Movie", "Video", "Audio", "TvChannel", "MusicVideo", "Trailer":
	default:
		// Ignore folders/collections/users/libraries unless clearly an episode/media with SeriesName or RunTimeTicks.
		if jsonStringField(m, "SeriesName") == "" && jsonInt64Field(m, "RunTimeTicks") <= 0 {
			return cachedMediaItem{}, false
		}
		if mediaType == "Series" || mediaType == "Season" || mediaType == "Folder" || mediaType == "CollectionFolder" || mediaType == "BoxSet" || mediaType == "Playlist" {
			return cachedMediaItem{}, false
		}
	}
	item := cachedMediaItem{
		ItemID:         id,
		MediaType:      mediaType,
		Title:          name,
		SeriesName:     jsonStringField(m, "SeriesName"),
		SeasonNumber:   int(jsonInt64Field(m, "ParentIndexNumber")),
		EpisodeNumber:  int(jsonInt64Field(m, "IndexNumber")),
		ProductionYear: int(jsonInt64Field(m, "ProductionYear")),
		DurationSec:    jsonInt64Field(m, "RunTimeTicks") / 10_000_000,
	}
	if sources, ok := m["MediaSources"].([]any); ok && len(sources) > 0 {
		if src, ok := sources[0].(map[string]any); ok {
			spec := parseMediaSourceFallbackItem(id, src)
			if item.DurationSec <= 0 {
				item.DurationSec = spec.DurationSec
			}
			item.VideoQuality = spec.VideoQuality
			item.Container = spec.Container
			item.Bitrate = spec.Bitrate
		}
	}
	return item, true
}

func parseMediaSourceFallbackItem(itemID string, src map[string]any) cachedMediaItem {
	rawName := jsonStringField(src, "Name")
	if rawName == "" {
		rawName = path.Base(strings.ReplaceAll(jsonStringField(src, "Path"), `\`, "/"))
	}
	item := parseFilenameFallbackItem(itemID, rawName)
	item.Container = strings.ToUpper(strings.TrimPrefix(jsonStringField(src, "Container"), "."))
	item.Bitrate = jsonInt64Field(src, "Bitrate")
	if ticks := jsonInt64Field(src, "RunTimeTicks"); ticks > 0 {
		item.DurationSec = ticks / 10_000_000
	}
	if streams, ok := src["MediaStreams"].([]any); ok {
		for _, rawStream := range streams {
			sm, ok := rawStream.(map[string]any)
			if !ok {
				continue
			}
			if !strings.EqualFold(jsonStringField(sm, "Type"), "Video") {
				continue
			}
			w := jsonInt64Field(sm, "Width")
			h := jsonInt64Field(sm, "Height")
			res := ""
			switch {
			case w >= 3800 || h >= 2100:
				res = "4K"
			case w >= 2500 || h >= 1400:
				res = "2K"
			case w >= 1800 || h >= 1000:
				res = "1080p"
			case w >= 1200 || h >= 700:
				res = "720p"
			case h > 0:
				res = fmt.Sprintf("%dp", h)
			}
			codec := strings.ToUpper(jsonStringField(sm, "Codec"))
			if codec == "H265" {
				codec = "HEVC"
			}
			vRange := strings.ToUpper(jsonStringField(sm, "VideoRangeType"))
			if vRange == "" || vRange == "SDR" {
				vRange = strings.ToUpper(jsonStringField(sm, "VideoRange"))
			}
			hdr := ""
			switch {
			case strings.Contains(vRange, "DOVI"), strings.Contains(vRange, "DOLBY"):
				hdr = "DV"
			case strings.Contains(vRange, "HDR"):
				hdr = "HDR"
			}
			parts := make([]string, 0, 3)
			if res != "" {
				parts = append(parts, res)
			}
			if codec != "" {
				parts = append(parts, codec)
			}
			if hdr != "" {
				parts = append(parts, hdr)
			}
			if len(parts) > 0 {
				item.VideoQuality = strings.Join(parts, " ")
			}
			break
		}
	}
	return item
}

func parseFilenameFallbackItem(itemID, raw string) cachedMediaItem {
	name := strings.TrimSpace(raw)
	if name == "" || name == "." || name == "/" {
		return cachedMediaItem{ItemID: itemID, FromFilename: true}
	}
	// Strip video extension
	ext := strings.ToLower(path.Ext(name))
	switch ext {
	case ".mkv", ".mp4", ".avi", ".mov", ".ts", ".m2ts", ".webm", ".flv", ".strm", ".iso", ".mp3", ".flac":
		name = strings.TrimSuffix(name, path.Ext(name))
	}
	item := cachedMediaItem{ItemID: itemID, FromFilename: true}
	if m := reResolutionTag.FindStringSubmatch(name); len(m) == 2 {
		tag := strings.ToUpper(m[1])
		if tag == "2160P" {
			tag = "4K"
		}
		item.VideoQuality = tag
	}
	if m := reSeasonEpisode.FindStringSubmatchIndex(name); len(m) == 6 {
		item.SeasonNumber, _ = strconv.Atoi(name[m[2]:m[3]])
		item.EpisodeNumber, _ = strconv.Atoi(name[m[4]:m[5]])
		series := strings.TrimSpace(strings.NewReplacer(".", " ", "_", " ").Replace(name[:m[0]]))
		if series != "" {
			item.SeriesName = series
			item.MediaType = "Episode"
		}
	}
	cleaned := strings.TrimSpace(strings.NewReplacer(".", " ", "_", " ").Replace(name))
	item.Title = truncateRunes(cleaned, 140)
	return item
}

func jsonStringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatInt(int64(t), 10)
	default:
		return ""
	}
}

func jsonInt64Field(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			return int64(f)
		}
	case float64:
		return int64(t)
	case int64:
		return t
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			return i
		}
	}
	return 0
}

func rawJSONToString(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return strings.Trim(trimmed, `"`)
}

/* -------------------- SQLite Watch History Persistence -------------------- */

func (s *telemetryStore) UpsertWatchHistory(ctx context.Context, sessions []playbackSessionSnapshot) error {
	if s == nil || len(sessions) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO watch_history (
			session_key, node_id, node_name, user_name, client_ip, client_name, device_name,
			upstream_host, item_id, media_type, title, series_name, season_number, episode_number,
			production_year, video_quality, play_method, position_sec, duration_sec, progress_pct,
			bytes_out, started_at, last_seen_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(session_key) DO UPDATE SET
			node_id = CASE WHEN excluded.node_id != '' THEN excluded.node_id ELSE watch_history.node_id END,
			node_name = CASE WHEN excluded.node_name != '' THEN excluded.node_name ELSE watch_history.node_name END,
			user_name = CASE WHEN excluded.user_name != '' THEN excluded.user_name ELSE watch_history.user_name END,
			client_name = CASE WHEN excluded.client_name != '' THEN excluded.client_name ELSE watch_history.client_name END,
			device_name = CASE WHEN excluded.device_name != '' THEN excluded.device_name ELSE watch_history.device_name END,
			media_type = CASE WHEN excluded.media_type != '' THEN excluded.media_type ELSE watch_history.media_type END,
			title = CASE WHEN excluded.title != '' AND (watch_history.title = '' OR watch_history.title LIKE '媒体 #%' OR excluded.series_name != '' OR excluded.media_type != '') THEN excluded.title ELSE watch_history.title END,
			series_name = CASE WHEN excluded.series_name != '' THEN excluded.series_name ELSE watch_history.series_name END,
			season_number = CASE WHEN excluded.season_number > 0 THEN excluded.season_number ELSE watch_history.season_number END,
			episode_number = CASE WHEN excluded.episode_number > 0 THEN excluded.episode_number ELSE watch_history.episode_number END,
			production_year = CASE WHEN excluded.production_year > 0 THEN excluded.production_year ELSE watch_history.production_year END,
			video_quality = CASE WHEN excluded.video_quality != '' THEN excluded.video_quality ELSE watch_history.video_quality END,
			play_method = CASE WHEN excluded.play_method != '' THEN excluded.play_method ELSE watch_history.play_method END,
			position_sec = MAX(watch_history.position_sec, excluded.position_sec),
			duration_sec = CASE WHEN excluded.duration_sec > 0 THEN excluded.duration_sec ELSE watch_history.duration_sec END,
			progress_pct = MAX(watch_history.progress_pct, excluded.progress_pct),
			bytes_out = MAX(watch_history.bytes_out, excluded.bytes_out),
			last_seen_at = MAX(watch_history.last_seen_at, excluded.last_seen_at)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, sess := range sessions {
		if sess.SessionKey == "" || sess.Title == "" {
			continue
		}
		if sess.ItemID != "" && sess.ClientIP != "" && sess.UpstreamHost != "" && !strings.Contains(sess.SessionKey, "|generic|") {
			hostLower := strings.ToLower(strings.TrimSpace(sess.UpstreamHost))
			prefix := ""
			includeUnprefixed := sess.NodeID == "" || sess.NodeID == "local"
			if sess.NodeID != "" {
				prefix = sess.NodeID + "|"
			}
			candKeys := []string{
				prefix + sess.ClientIP + "|generic|" + hostLower + "|" + sess.ItemID,
			}
			if includeUnprefixed && prefix != "" {
				candKeys = append(candKeys, sess.ClientIP+"|generic|"+hostLower+"|"+sess.ItemID)
			}
			if sess.ClientName != "" {
				cLower := strings.ToLower(strings.TrimSpace(sess.ClientName))
				if k1 := prefix + sess.ClientIP + "|" + cLower + "|" + hostLower + "|" + sess.ItemID; k1 != sess.SessionKey {
					candKeys = append(candKeys, k1)
				}
				if includeUnprefixed && prefix != "" {
					if k2 := sess.ClientIP + "|" + cLower + "|" + hostLower + "|" + sess.ItemID; k2 != sess.SessionKey {
						candKeys = append(candKeys, k2)
					}
				}
			}
			for _, weakKey := range candKeys {
				var prevBytes, prevStarted int64
				if qErr := tx.QueryRowContext(ctx,
					`SELECT bytes_out, started_at FROM watch_history WHERE session_key=? AND ABS(last_seen_at - ?) <= 900`,
					weakKey, sess.LastSeenAt,
				).Scan(&prevBytes, &prevStarted); qErr == nil {
					if prevBytes > sess.BytesOut {
						sess.BytesOut = prevBytes
					}
					if prevStarted > 0 && (sess.StartedAt == 0 || prevStarted < sess.StartedAt) {
						sess.StartedAt = prevStarted
					}
					_, _ = tx.ExecContext(ctx, `DELETE FROM watch_history WHERE session_key=?`, weakKey)
				}
			}
		}
		if !strings.HasPrefix(sess.Title, "媒体 #") && sess.ItemID != "" && sess.ClientIP != "" && sess.UpstreamHost != "" {
			parts := strings.Split(sess.SessionKey, "|")
			dev := ""
			if len(parts) == 5 && sess.NodeID != "" {
				dev = parts[2]
			} else if len(parts) == 4 {
				dev = parts[1]
			}
			if dev != "" && dev != "generic" && !strings.EqualFold(dev, sess.ClientName) {
				if lastPipe := strings.LastIndex(sess.SessionKey, "|"); lastPipe > 0 {
					keyPrefix := sess.SessionKey[:lastPipe+1]
					type orphanTwin struct {
						key     string
						bytes   int64
						started int64
					}
					var orphans []orphanTwin
					if rows, qErr := tx.QueryContext(ctx, `
						SELECT session_key, bytes_out, started_at
						FROM watch_history
						WHERE substr(session_key, 1, length(?)) = ?
						  AND session_key != ?
						  AND title LIKE '媒体 #%'
						  AND media_type = ''
						  AND position_sec = 0
						  AND ABS(last_seen_at - ?) <= 120`,
						keyPrefix, keyPrefix, sess.SessionKey, sess.LastSeenAt,
					); qErr == nil {
						for rows.Next() {
							var o orphanTwin
							if rows.Scan(&o.key, &o.bytes, &o.started) == nil {
								orphans = append(orphans, o)
							}
						}
						_ = rows.Close()
					}
					for _, o := range orphans {
						if o.bytes > sess.BytesOut {
							sess.BytesOut = o.bytes
						}
						if o.started > 0 && (sess.StartedAt == 0 || o.started < sess.StartedAt) {
							sess.StartedAt = o.started
						}
						_, _ = tx.ExecContext(ctx, `DELETE FROM watch_history WHERE session_key=?`, o.key)
					}
				}
			}
		}
		if _, err := stmt.ExecContext(ctx,
			sess.SessionKey, sess.NodeID, sess.NodeName, sess.UserName, sess.ClientIP,
			sess.ClientName, sess.DeviceName, sess.UpstreamHost, sess.ItemID, sess.MediaType,
			sess.Title, sess.SeriesName, sess.SeasonNumber, sess.EpisodeNumber,
			sess.ProductionYear, sess.VideoQuality, sess.PlayMethod,
			sess.PositionSec, sess.DurationSec, sess.ProgressPct,
			sess.BytesOut, sess.StartedAt, sess.LastSeenAt,
		); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-playbackHistoryRetention).Unix()
	_, _ = tx.ExecContext(ctx, `DELETE FROM watch_history WHERE last_seen_at < ?`, cutoff)
	_, _ = tx.ExecContext(ctx, `DELETE FROM watch_history WHERE session_key NOT IN (SELECT session_key FROM watch_history ORDER BY last_seen_at DESC LIMIT ?)`, playbackHistoryMaxRows)
	return tx.Commit()
}

func (s *telemetryStore) ListWatchHistory(ctx context.Context, nodeID string, limit int) ([]watchHistoryRecord, int, error) {
	if s == nil {
		return []watchHistoryRecord{}, 0, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	since24h := time.Now().Add(-24 * time.Hour).Unix()
	var count24h int
	if nodeID != "" && nodeID != "all" {
		_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM watch_history WHERE last_seen_at >= ? AND node_id = ?`, since24h, nodeID).Scan(&count24h)
	} else {
		_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM watch_history WHERE last_seen_at >= ?`, since24h).Scan(&count24h)
	}

	var rows *sql.Rows
	var err error
	if nodeID != "" && nodeID != "all" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT session_key, node_id, node_name, user_name, client_ip, client_name, device_name,
			       upstream_host, item_id, media_type, title, series_name, season_number, episode_number,
			       production_year, video_quality, play_method, position_sec, duration_sec, progress_pct,
			       bytes_out, started_at, last_seen_at
			FROM watch_history WHERE node_id = ? ORDER BY last_seen_at DESC LIMIT ?`, nodeID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT session_key, node_id, node_name, user_name, client_ip, client_name, device_name,
			       upstream_host, item_id, media_type, title, series_name, season_number, episode_number,
			       production_year, video_quality, play_method, position_sec, duration_sec, progress_pct,
			       bytes_out, started_at, last_seen_at
			FROM watch_history ORDER BY last_seen_at DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, count24h, err
	}
	defer rows.Close()
	out := make([]watchHistoryRecord, 0, limit)
	for rows.Next() {
		var r watchHistoryRecord
		if err := rows.Scan(
			&r.SessionKey, &r.NodeID, &r.NodeName, &r.UserName, &r.ClientIP, &r.ClientName, &r.DeviceName,
			&r.UpstreamHost, &r.ItemID, &r.MediaType, &r.Title, &r.SeriesName, &r.SeasonNumber, &r.EpisodeNumber,
			&r.ProductionYear, &r.VideoQuality, &r.PlayMethod, &r.PositionSec, &r.DurationSec, &r.ProgressPct,
			&r.BytesOut, &r.StartedAt, &r.LastSeenAt,
		); err != nil {
			return nil, count24h, err
		}
		out = append(out, r)
	}
	return out, count24h, rows.Err()
}

func (s *telemetryStore) EnrichPlaybackLocations(ctx context.Context, active []playbackSessionSnapshot, history []watchHistoryRecord) {
	if s == nil || (len(active) == 0 && len(history) == 0) {
		return
	}
	unique := make(map[string]struct{}, len(active)+len(history))
	for _, a := range active {
		if a.ClientIP != "" {
			unique[a.ClientIP] = struct{}{}
		}
	}
	for _, h := range history {
		if h.ClientIP != "" {
			unique[h.ClientIP] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return
	}
	args := make([]any, 0, len(unique))
	ph := make([]string, 0, len(unique))
	for ip := range unique {
		args = append(args, ip)
		ph = append(ph, "?")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip,country,country_code,region FROM geo_ip_cache WHERE ip IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return
	}
	defer rows.Close()
	locs := make(map[string]string, len(unique))
	for rows.Next() {
		var ip, country, code, region string
		if rows.Scan(&ip, &country, &code, &region) == nil && code != "" {
			_, _, label, _ := geographyRegion(country, code, region)
			locs[ip] = label
		}
	}
	for i := range active {
		if loc := locs[active[i].ClientIP]; loc != "" {
			active[i].Location = loc
		}
	}
	for i := range history {
		if loc := locs[history[i].ClientIP]; loc != "" {
			history[i].Location = loc
		}
	}
}
