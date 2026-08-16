package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	expiresParam   = "__vug_exp"
	signatureParam = "__vug_sig"
)

type Signer struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

func NewSigner(secret []byte, ttl time.Duration) Signer {
	return Signer{secret: append([]byte(nil), secret...), ttl: ttl, now: time.Now}
}

func (s Signer) Sign(target *url.URL) (expires string, signature string) {
	expires = strconv.FormatInt(s.now().Add(s.ttl).Unix(), 10)
	return expires, s.signature(target, expires)
}

func (s Signer) Verify(target *url.URL, expires, signature string) bool {
	expiresUnix, err := strconv.ParseInt(expires, 10, 64)
	if err != nil || expiresUnix < s.now().Unix() {
		return false
	}
	maxExpiry := s.now().Add(s.ttl + 5*time.Minute).Unix()
	if expiresUnix > maxExpiry {
		return false
	}
	expected := s.signature(target, expires)
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(signature)))
}

func (s Signer) signature(target *url.URL, expires string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(canonicalTarget(target)))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(expires))
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalTarget(target *url.URL) string {
	copyURL := *target
	copyURL.Fragment = ""
	return copyURL.String()
}

func appendGatewaySignature(rawQuery, expires, signature string) string {
	parts := make([]string, 0, 3)
	if rawQuery != "" {
		parts = append(parts, rawQuery)
	}
	parts = append(parts, url.QueryEscape(expiresParam)+"="+url.QueryEscape(expires))
	parts = append(parts, url.QueryEscape(signatureParam)+"="+url.QueryEscape(signature))
	return strings.Join(parts, "&")
}

func stripGatewaySignature(rawQuery string) (cleanQuery, expires, signature string, err error) {
	if rawQuery == "" {
		return "", "", "", nil
	}
	kept := make([]string, 0, strings.Count(rawQuery, "&")+1)
	for _, part := range strings.Split(rawQuery, "&") {
		keyPart, valuePart, _ := strings.Cut(part, "=")
		key, decodeErr := url.QueryUnescape(keyPart)
		if decodeErr != nil {
			return "", "", "", fmt.Errorf("invalid query parameter")
		}
		value, decodeErr := url.QueryUnescape(valuePart)
		if decodeErr != nil {
			return "", "", "", fmt.Errorf("invalid query parameter")
		}
		switch key {
		case expiresParam:
			if expires != "" {
				return "", "", "", fmt.Errorf("duplicate signature expiry")
			}
			expires = value
		case signatureParam:
			if signature != "" {
				return "", "", "", fmt.Errorf("duplicate signature")
			}
			signature = value
		default:
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "&"), expires, signature, nil
}
