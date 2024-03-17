package security

import (
	"github.com/adrian-lorenz/noxway/global"
	"github.com/adrian-lorenz/noxway/tools"
	"slices"
)

func CheckWhitelists(ip string) bool {
	if ip == "" {
		return false
	}
	if len(global.Config.SystemWhitelist) > 0 {
		if slices.Contains(global.Config.SystemWhitelist, ip) {
			return true
		}
	}
	if len(global.Config.SystemWhitelistDNS) > 0 {
		for _, w := range global.Config.SystemWhitelistDNS {
			dnsIp, err := tools.GetDnsIP(w)
			if err != nil {
				return false
			}
			if dnsIp == ip {
				return true
			}
		}
	}
	return false
}
