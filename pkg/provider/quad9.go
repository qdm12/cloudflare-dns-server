package provider

import (
	"net"
	"net/url"
)

type quad9 struct{}

func Quad9() Provider {
	return &quad9{}
}

func (q *quad9) String() string {
	return "Quad9"
}

func (q *quad9) DNS() DNSServer {
	return DNSServer{
		IPv4: []net.IP{{9, 9, 9, 9}, {149, 112, 112, 112}},
		IPv6: []net.IP{
			{0x26, 0x20, 0x0, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfe},
			{0x26, 0x20, 0x0, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9},
		},
	}
}

func (q *quad9) DoT() DoTServer {
	return DoTServer{
		IPv4: []net.IP{{9, 9, 9, 9}, {149, 112, 112, 112}},
		IPv6: []net.IP{
			{0x26, 0x20, 0x0, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfe},
			{0x26, 0x20, 0x0, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9},
		},
		Name: "dns.quad9.net",
		Port: defaultDoTPort,
	}
}

func (q *quad9) DoH() DoHServer {
	// See https://developers.quad9.com/speed/public-dns/docs/doh
	return DoHServer{
		URL: &url.URL{
			Scheme: "https",
			Host:   "dns.quad9.net",
			Path:   "/dns-query",
		},
	}
}
