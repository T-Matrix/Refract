package gateway

import (
	"net/http"
	"strings"
)

type deviceIdentity struct {
	ID         string
	DeviceName string
	ClientName string
}

func requestDeviceIdentity(request *http.Request) deviceIdentity {
	identity := deviceIdentity{}
	for _, name := range []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "Authorization"} {
		parsed := parseDeviceIdentityHeader(request.Header.Get(name))
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
	if identity.ID == "" {
		for _, name := range []string{"X-Emby-Device-Id", "X-MediaBrowser-Device-Id"} {
			if deviceID := strings.TrimSpace(request.Header.Get(name)); deviceID != "" {
				identity.ID = deviceID
				break
			}
		}
	}
	if identity.ClientName == "" {
		for _, name := range []string{"X-Emby-Client", "X-MediaBrowser-Client"} {
			if clientName := strings.TrimSpace(request.Header.Get(name)); clientName != "" {
				identity.ClientName = clientName
				break
			}
		}
	}
	if identity.DeviceName == "" {
		for _, name := range []string{"X-Emby-Device-Name", "X-MediaBrowser-Device-Name"} {
			if deviceName := strings.TrimSpace(request.Header.Get(name)); deviceName != "" {
				identity.DeviceName = deviceName
				break
			}
		}
	}
	if identity.ID != "" || identity.ClientName != "" || identity.DeviceName != "" {
		return identity
	}
	for _, key := range []string{"DeviceId", "device_id", "deviceId"} {
		if deviceID := strings.TrimSpace(request.URL.Query().Get(key)); deviceID != "" {
			return deviceIdentity{ID: deviceID}
		}
	}
	return deviceIdentity{}
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
	if space := strings.IndexAny(raw, " \t"); space >= 0 {
		raw = raw[space+1:]
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
