package dnssec

import "github.com/miekg/dns"

func WithDNSSEC(message *dns.Msg) {
	message.MsgHdr.RecursionDesired = true
	const maxUDPSize = 4096
	message.SetEdns0(maxUDPSize, true)
}
