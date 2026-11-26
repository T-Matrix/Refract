package gateway

import (
	"net/http"
	"net/url"
	"strings"
)

type deviceIdentity struct {
	ID         string
	DeviceName string
	ClientName string
}

func requestDeviceIdentity(request *http.Request) deviceIdentity {
	return requestDeviceIdentityForTarget(request, nil)
}

func requestDeviceIdentityForTarget(request *http.Request, target *url.URL) deviceIdentity {
	identity := deviceIdentity{}
	if request == nil {
		return identity
	}
	mergeParsed := func(raw string) {
		parsed := parseDeviceIdentityHeader(raw)
		if identity.ID == "" {
			identity.ID = parsed.ID
		}
		if identity.DeviceName == "" {
			identity.DeviceName = parsed.DeviceName
		}
		if identity.ClientName == "" {
			identity.ClientName = parsed.ClientName
		}
	}
	for _, name := range []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "Authorization"} {
		for _, raw := range request.Header.Values(name) {
			mergeParsed(raw)
		}
	}
	if identity.ID == "" {
		for _, name := range []string{"X-Emby-Device-Id", "X-MediaBrowser-Device-Id"} {
			for _, raw := range request.Header.Values(name) {
				if deviceID := strings.TrimSpace(raw); deviceID != "" {
					identity.ID = deviceID
					break
				}
			}
			if identity.ID != "" {
				break
			}
		}
	}
	if identity.ClientName == "" {
		for _, name := range []string{"X-Emby-Client", "X-MediaBrowser-Client"} {
			for _, raw := range request.Header.Values(name) {
				if clientName := strings.TrimSpace(raw); clientName != "" {
					identity.ClientName = clientName
					break
				}
			}
			if identity.ClientName != "" {
				break
			}
		}
	}
	if identity.DeviceName == "" {
		for _, name := range []string{"X-Emby-Device-Name", "X-MediaBrowser-Device-Name"} {
			for _, raw := range request.Header.Values(name) {
				if deviceName := strings.TrimSpace(raw); deviceName != "" {
					identity.DeviceName = deviceName
					break
				}
			}
			if identity.DeviceName != "" {
				break
			}
		}
	}
	mergeQuery := func(rawQuery string) {
		if rawQuery == "" || (identity.ID != "" && identity.ClientName != "" && identity.DeviceName != "") {
			return
		}
		parsed, err := url.ParseQuery(rawQuery)
		if err != nil {
			return
		}
		lowerVals := make(map[string]string, len(parsed))
		for k, vals := range parsed {
			lk := strings.ToLower(strings.TrimSpace(k))
			if lk == "" {
				continue
			}
			if _, exists := lowerVals[lk]; exists {
				continue
			}
			for _, v := range vals {
				if trimmed := strings.TrimSpace(v); trimmed != "" {
					lowerVals[lk] = trimmed
					break
				}
			}
		}
		for _, key := range []string{"x-emby-authorization", "x-mediabrowser-authorization"} {
			if raw := lowerVals[key]; raw != "" {
				mergeParsed(raw)
			}
		}
		if identity.ClientName == "" {
			for _, key := range []string{"x-emby-client", "x-mediabrowser-client", "client"} {
				if v := lowerVals[key]; v != "" {
					identity.ClientName = v
					break
				}
			}
		}
		if identity.DeviceName == "" {
			for _, key := range []string{"x-emby-device-name", "x-mediabrowser-device-name"} {
				if v := lowerVals[key]; v != "" {
					identity.DeviceName = v
					break
				}
			}
		}
		if identity.ID == "" {
			for _, key := range []string{"x-emby-device-id", "x-mediabrowser-device-id", "deviceid", "device_id"} {
				if v := lowerVals[key]; v != "" {
					identity.ID = v
					break
				}
			}
		}
	}
	if request.URL != nil && request.URL.RawQuery != "" {
		mergeQuery(request.URL.RawQuery)
	}
	if target != nil && target.RawQuery != "" {
		mergeQuery(target.RawQuery)
	}
	return identity
}

func parseDeviceIdentityHeader(raw string) deviceIdentity {
	fields := parseMediaBrowserParameters(raw)
	return deviceIdentity{
		ID:         fields["deviceid"],
		DeviceName: fields["device"],
		ClientName: fields["client"],
	}
}

func parseMediaBrowserParameters(raw string) map[string]string {
	fields := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fields
	}
	// Strip an optional auth scheme prefix (e.g. "MediaBrowser ", "Emby ") only when
	// the leading token itself is NOT already a key=value parameter.
	if space := strings.IndexAny(raw, " \t"); space >= 0 {
		firstToken := raw[:space]
		if !strings.ContainsAny(firstToken, "=,") {
			raw = raw[space+1:]
		}
	}
	for index := 0; index < len(raw); {
		for index < len(raw) && (raw[index] == ',' || raw[index] == ' ' || raw[index] == '\t') {
			index++
		}
		if index >= len(raw) {
			break
		}
		keyStart := index
		for index < len(raw) && raw[index] != '=' && raw[index] != ',' {
			index++
		}
		if index >= len(raw) || raw[index] != '=' {
			for index < len(raw) && raw[index] != ',' {
				index++
			}
			continue
		}
		key := strings.ToLower(strings.TrimSpace(raw[keyStart:index]))
		index++
		for index < len(raw) && (raw[index] == ' ' || raw[index] == '\t') {
			index++
		}
		value := ""
		if index < len(raw) && raw[index] == '"' {
			index++
			var builder strings.Builder
			for index < len(raw) {
				char := raw[index]
				index++
				if char == '\\' && index < len(raw) {
					builder.WriteByte(raw[index])
					index++
					continue
				}
				if char == '"' {
					break
				}
				builder.WriteByte(char)
			}
			value = builder.String()
		} else {
			valueStart := index
			for index < len(raw) && raw[index] != ',' {
				index++
			}
			value = strings.TrimSpace(raw[valueStart:index])
		}
		if key != "" {
			fields[key] = value
		}
		for index < len(raw) && raw[index] != ',' {
			index++
		}
	}
	return fields
}
