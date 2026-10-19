package gateway

import (
	"net/url"
	"strings"
)

type embyHealthLabel struct {
	host         string
	port         string
	explicitPort bool
	serverName   string
	groupName    string
	lineName     string
	note         string
}

func buildEmbyHealthLabels(servers []embyHealthServer) []embyHealthLabel {
	labels := make([]embyHealthLabel, 0, len(servers))
	for _, server := range servers {
		if !server.Enabled {
			continue
		}
		parsed, err := url.Parse(server.BaseURL)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		labels = append(labels, embyHealthLabel{
			host:         normalizeHost(parsed.Hostname()),
			port:         effectivePort(parsed),
			explicitPort: parsed.Port() != "",
			serverName:   server.Name,
			groupName:    server.GroupName,
			lineName:     server.LineName,
			note:         server.Note,
		})
	}
	return labels
}

func matchEmbyHealthLabel(host, scheme string, labels []embyHealthLabel) *embyHealthLabel {
	parsed, err := url.Parse("//" + strings.TrimSpace(host))
	if err != nil || parsed.Hostname() == "" {
		return nil
	}
	hostname := normalizeHost(parsed.Hostname())
	explicitPort := parsed.Port() != ""
	targetPort := parsed.Port()
	if !explicitPort && strings.TrimSpace(scheme) != "" {
		targetPort = effectivePort(&url.URL{Scheme: strings.ToLower(strings.TrimSpace(scheme))})
	}

	var candidates []*embyHealthLabel
	for index := range labels {
		label := &labels[index]
		if label.host != hostname {
			continue
		}
		if explicitPort {
			if label.port == targetPort {
				candidates = append(candidates, label)
			}
			continue
		}
		if targetPort != "" {
			if label.port == targetPort {
				candidates = append(candidates, label)
			}
			continue
		}
		if !label.explicitPort {
			candidates = append(candidates, label)
		}
	}
	if len(candidates) != 1 {
		return nil
	}
	return candidates[0]
}

func decorateTargetSummaries(targets []targetSummary, servers []embyHealthServer) {
	labels := buildEmbyHealthLabels(servers)
	for index := range targets {
		label := matchEmbyHealthLabel(targets[index].Host, "", labels)
		if label == nil {
			continue
		}
		targets[index].EmbyServerName = label.serverName
		targets[index].EmbyGroupName = label.groupName
		targets[index].EmbyLineName = label.lineName
		targets[index].EmbyNote = label.note
	}
}

func decorateRequestLogs(logs []requestLog, servers []embyHealthServer) {
	labels := buildEmbyHealthLabels(servers)
	for index := range logs {
		label := matchEmbyHealthLabel(logs[index].Host, logs[index].Scheme, labels)
		if label == nil {
			continue
		}
		logs[index].EmbyServerName = label.serverName
		logs[index].EmbyGroupName = label.groupName
		logs[index].EmbyLineName = label.lineName
		logs[index].EmbyNote = label.note
	}
}
