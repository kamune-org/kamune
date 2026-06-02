package handlers

import (
	"net"
	"net/http"
	"strings"
)

var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range cidrs {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil {
			privateRanges = append(privateRanges, block)
		}
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func extractIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

func validateIP(s string) string {
	raw := extractIP(s)
	if raw == "" {
		return ""
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func singleHeader(r *http.Request, name string) string {
	return validateIP(r.Header.Get(name))
}

func clientIP(r *http.Request) string {
	for _, header := range []string{
		"X-Real-Ip",
		"True-Client-IP",
		"CF-Connecting-IP",
		"Fly-Client-IP",
		"Fastly-Client-IP",
	} {
		if ip := singleHeader(r, header); ip != "" {
			return ip
		}
	}

	if ip := ParseForwardedIP(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}

	ip := validateIP(r.RemoteAddr)
	if ip != "" {
		return ip
	}
	return extractIP(r.RemoteAddr)
}

func ParseForwardedIP(header string) string {
	if header == "" {
		return ""
	}

	var firstValid string
	for _, part := range strings.Split(header, ",") {
		ip := validateIP(part)
		if ip == "" {
			continue
		}
		if firstValid == "" {
			firstValid = ip
		}
		parsed := net.ParseIP(ip)
		if parsed != nil && !isPrivateIP(parsed) {
			return ip
		}
	}
	return firstValid
}
