package models

import (
	"net"
	"strconv"
	"strings"
)

const (
	subIndent = " |--"
	indent    = "    " // used if lines already contain the subIndent
)

// Settings represents all the user settings for Unbound.
type Settings struct {
	Providers             []string
	ListeningPort         uint16
	Caching               bool
	IPv4                  bool
	IPv6                  bool
	VerbosityLevel        uint8
	VerbosityDetailsLevel uint8
	ValidationLogLevel    uint8
	BlockedHostnames      []string
	BlockedIPs            []string
	AllowedHostnames      []string
	AccessControl         AccessControlSettings
}

func (s *Settings) String() string {
	return strings.Join(s.Lines(), "\n")
}

func (s *Settings) Lines() (lines []string) {
	const (
		disabled = "disabled"
		enabled  = "enabled"
	)

	lines = append(lines, subIndent+"DNS over TLS providers:")
	for _, provider := range s.Providers {
		lines = append(lines, indent+subIndent+provider)
	}

	lines = append(lines,
		subIndent+"Listening port: "+strconv.Itoa(int(s.ListeningPort)))

	lines = append(lines, subIndent+"Access control:")
	for _, line := range s.AccessControl.Lines() {
		lines = append(lines, indent+line)
	}

	caching := disabled
	if s.Caching {
		caching = enabled
	}
	lines = append(lines, subIndent+
		"Caching: "+caching)

	ipv4 := disabled
	if s.IPv4 {
		ipv4 = enabled
	}
	lines = append(lines, subIndent+
		"IPv4 resolution: "+ipv4)

	ipv6 := disabled
	if s.IPv6 {
		ipv6 = enabled
	}
	lines = append(lines, subIndent+
		"IPv6 resolution: "+ipv6)

	lines = append(lines, subIndent+
		"Verbosity level: "+strconv.Itoa(int(s.VerbosityLevel))+"/5")

	lines = append(lines, subIndent+
		"Verbosity details level: "+strconv.Itoa(int(s.VerbosityDetailsLevel))+"/4")

	lines = append(lines, subIndent+
		"Validation log level: "+strconv.Itoa(int(s.ValidationLogLevel))+"/2")

	lines = append(lines, subIndent+"Blocked hostnames:")
	for _, hostname := range s.BlockedHostnames {
		lines = append(lines, indent+subIndent+hostname)
	}

	lines = append(lines, subIndent+"Blocked IP addresses:")
	for _, ip := range s.BlockedIPs {
		lines = append(lines, indent+subIndent+ip)
	}

	lines = append(lines, subIndent+"Allowed hostnames:")
	for _, hostname := range s.AllowedHostnames {
		lines = append(lines, indent+subIndent+hostname)
	}

	return lines
}

type AccessControlSettings struct {
	Allowed []net.IPNet
}

func (s *AccessControlSettings) Lines() (lines []string) {
	lines = append(lines, subIndent+"Allowed:")
	for _, subnet := range s.Allowed {
		lines = append(lines,
			indent+subIndent+subnet.String())
	}
	return lines
}
