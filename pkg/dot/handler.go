package dot

import (
	"context"
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/qdm12/dns/pkg/dnssec"
	"github.com/qdm12/golibs/logging"
)

type handler struct {
	// External objects
	ctx    context.Context
	logger logging.Logger

	// Internal objects
	dial          func(ctx context.Context, _, _ string) (net.Conn, error)
	udpBufferPool *sync.Pool
	client        *dns.Client
}

func newDNSHandler(ctx context.Context, logger logging.Logger,
	options ...Option) dns.Handler {
	settings := defaultSettings()
	for _, option := range options {
		option(&settings)
	}

	const dnsPacketMaxSize = 512
	udpBufferPool := &sync.Pool{
		New: func() interface{} {
			return make([]byte, dnsPacketMaxSize)
		},
	}

	return &handler{
		ctx:           ctx,
		logger:        logger,
		dial:          newDoTDial(settings),
		udpBufferPool: udpBufferPool,
		client:        &dns.Client{},
	}
}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	DoTConn, err := h.dial(h.ctx, "", "")
	if err != nil {
		h.logger.Warn("cannot dial: %s", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}
	conn := &dns.Conn{Conn: DoTConn}

	dnssec.WithDNSSEC(r)

	response, _, err := h.client.ExchangeWithConn(r, conn)

	if err := conn.Close(); err != nil {
		h.logger.Warn("cannot close the DoT connection: %s", err)
	}

	if err != nil {
		h.logger.Warn("cannot exchange over DoT connection: %s", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}

	// Extract signature for DNSSEC
	rrsig, rrset, err := dnssec.ExtractRRSIG(response)
	if err != nil {
		h.logger.Warn("cannot extract DNSSEC signature: %s", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}

	if rrsig == nil { // not signed with DNSSEC
		// TODO strict mode
		if err := w.WriteMsg(response); err != nil {
			h.logger.Warn("cannot write DNS message back to client: %s", err)
		}
		return
	}

	signerName := rrsig.SignerName
	chain := dnssec.NewAuthenticationChain(h.client, h.dial)
	if err := chain.Populate(h.ctx, signerName); err != nil {
		h.logger.Warn("DNSSEC auth chain populating failed: %s", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}

	if err := chain.Verify(rrsig, rrset); err != nil {
		h.logger.Warn("DNSSEC validation failed: %s", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		// TODO RcodeBadSig
		return
	}

	if err := w.WriteMsg(response); err != nil {
		h.logger.Warn("cannot write DNS message back to client: %s", err)
	}
}
