package main

import (
	"flag"
	"fmt"
	"os"

	"plutoploy/tls/internal/ip"
)

func main() {
	domainFlag := flag.String("domain", ".example.com", "Base domain to append to the hex-encoded IP")
	flag.Parse()

	subdomain, err := ip.GetSubdomain(*domainFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Dynamic Subdomain:", subdomain)
}
