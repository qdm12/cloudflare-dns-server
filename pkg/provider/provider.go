package provider

import (
	"net"
	"net/url"
)

//go:generate mockgen -destination=mock_$GOPACKAGE/$GOFILE . Provider

const defaultDoTPort uint16 = 853

type Provider interface {
	DNS() DNSServer
	DoT() DoTServer
	DoH() DoHServer
	String() string
}

type DNSServer struct {
	IPv4 []net.IP
	IPv6 []net.IP
}

type DoTServer struct {
	IPv4 []net.IP
	IPv6 []net.IP
	Name string // for TLS verification
	Port uint16
}

type DoHServer struct {
	URL *url.URL
}
