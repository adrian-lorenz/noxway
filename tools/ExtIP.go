package tools

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
)

func GetExtIP() (string, error) {
	url := "https://api.ipify.org"
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil

}

func GetDnsIP(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found for %s", hostname)
}

func GetDnsIPWithResolver(hostname, resolver string) (string, error) {
	var r *net.Resolver
	if resolver != "" {
		addr := resolver
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = addr + ":53"
		}
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", addr)
			},
		}
	} else {
		r = net.DefaultResolver
	}
	ips, err := r.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ipv4 := ip.IP.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for %s", hostname)
}
