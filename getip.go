package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

func getsubdomain(domain string) string {
	resp, err := http.Get("https://ifconfig.me/ip")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	ipBytes, _ := io.ReadAll(resp.Body)
	ipStr := strings.TrimSpace(string(ipBytes))

	fmt.Println(ipStr)

	ip := net.ParseIP(ipStr)
	if ip.To4() != nil {
		ipv4 := ip.To4()
		hexStr := fmt.Sprintf("%02x%02x%02x%02x", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		fmt.Println("Hex:", "0x"+strings.ToUpper(hexStr))
		return hexStr + domain
	} else {
		hexStr := hex.EncodeToString(ip)
		fmt.Println(strings.ToUpper(hexStr))
		return strings.ToUpper(hexStr) + domain
	}
}

