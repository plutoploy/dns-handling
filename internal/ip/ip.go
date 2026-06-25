package ip

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// GetSubdomain retrieves the public IP address and returns a hex-encoded subdomain.
func GetSubdomain(domain string) (string, error) {
	resp, err := http.Get("https://ifconfig.me/ip")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ipStr := strings.TrimSpace(string(ipBytes))

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address returned: %s", ipStr)
	}

	suffix := domain
	if suffix != "" && !strings.HasPrefix(suffix, ".") {
		suffix = "." + suffix
	}

	if ip.To4() != nil {
		ipv4 := ip.To4()
		hexStr := fmt.Sprintf("%02x%02x%02x%02x", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		return "dns." + hexStr + suffix, nil
	} else {
		hexStr := hex.EncodeToString(ip)
		return "dns." + hexStr + suffix, nil
	}
}
