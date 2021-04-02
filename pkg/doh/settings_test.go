package doh

import (
	"testing"
	"time"

	"github.com/qdm12/dns/pkg/blacklist"
	"github.com/qdm12/dns/pkg/cache"
	"github.com/qdm12/dns/pkg/provider"
	"github.com/stretchr/testify/assert"
)

func Test_ServerSettings_setDefaults(t *testing.T) {
	t.Parallel()

	s := ServerSettings{}
	s.setDefaults()

	// Check this otherwise things will blow up if no option is passed.
	assert.GreaterOrEqual(t, len(s.Resolver.DoHProviders), 1)
	assert.GreaterOrEqual(t, len(s.Resolver.SelfDNS.DoTProviders), 1)
	assert.Empty(t, s.Resolver.SelfDNS.DNSProviders)
	assert.GreaterOrEqual(t, int64(s.Resolver.Timeout), int64(time.Millisecond))

	expectedSettings := ServerSettings{
		Resolver: ResolverSettings{
			DoHProviders: []provider.Provider{provider.Cloudflare()},
			SelfDNS: SelfDNS{
				DoTProviders: []provider.Provider{provider.Cloudflare()},
			},
			Timeout: 5 * time.Second,
			IPv6:    false,
		},
		Port:  53,
		Cache: cache.Settings{},
	}
	assert.Equal(t, expectedSettings, s)
}

func Test_ServerSettings_Lines(t *testing.T) {
	t.Parallel()

	s := ServerSettings{
		Blacklist: blacklist.Settings{
			FqdnHostnames: []string{"abc.com"},
		},
		Cache: cache.Settings{
			Type: cache.LRU,
		},
	}
	s.setDefaults()

	lines := s.Lines(indent, subSection)

	expectedLines := []string{
		" |--Listening port: 53",
		" |--Resolver:",
		"     |--Connecting over: IPv4",
		"     |--Query timeout: 5s",
		"     |--DNS over HTTPS providers:",
		"         |--Cloudflare",
		"     |--Internal DNS:",
		"         |--DNS over TLS providers:",
		"             |--Cloudflare",
		" |--Caching:",
		"     |--Type: lru",
		"     |--Max entries: 100000",
		"     |--Entry TTL: 1h0m0s",
		" |--Blacklist:",
		"     |--Hostnames blocked: 1",
	}
	assert.Equal(t, expectedLines, lines)
}
