package dot

import (
	"time"

	"github.com/qdm12/dns/pkg/provider"
)

type Option func(s *settings)

func Providers(first provider.Provider, providers ...provider.Provider) Option {
	providers = append(providers, first)
	servers := make([]provider.DoTServer, len(providers))
	for i := range providers {
		servers[i] = providers[i].DoT()
	}
	return func(s *settings) {
		s.dotServers = servers
	}
}

func WithDNSFallback(first provider.Provider, providers ...provider.Provider) Option {
	providers = append(providers, first)
	servers := make([]provider.DNSServer, len(providers))
	for i := range providers {
		servers[i] = providers[i].DNS()
	}
	return func(s *settings) {
		s.dnsServers = servers
	}
}

func Timeout(timeout time.Duration) Option {
	return func(s *settings) {
		s.timeout = timeout
	}
}

func IPv4() Option {
	return func(s *settings) { s.ipv6 = false }
}

func IPv6() Option {
	return func(s *settings) { s.ipv6 = true }
}
