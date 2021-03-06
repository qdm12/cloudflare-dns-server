package provider

import (
	"net"
	"net/url"
)

type cloudflare struct{}

func Cloudflare() Provider {
	return &cloudflare{}
}

func (c *cloudflare) String() string {
	return "Cloudflare"
}

func (c *cloudflare) DNS() DNSServer {
	return DNSServer{
		IPv4: []net.IP{{1, 1, 1, 1}, {1, 0, 0, 1}},
		IPv6: []net.IP{
			{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11},
			{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x01},
		},
	}
}

func (c *cloudflare) DoT() DoTServer {
	return DoTServer{
		IPv4: []net.IP{{1, 1, 1, 1}, {1, 0, 0, 1}},
		IPv6: []net.IP{
			{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11},
			{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x01},
		},
		Name: "cloudflare-dns.com",
		Port: defaultDoTPort,
	}
}

func (c *cloudflare) DoH() DoHServer {
	return DoHServer{
		URL: &url.URL{
			Scheme: "https",
			Host:   "cloudflare-dns.com",
			Path:   "/dns-query",
		},
	}
}
