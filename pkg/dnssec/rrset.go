package dnssec

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

// type RRSet struct {
// 	rrSet []dns.RR
// 	rrSig *dns.RRSIG
// }

func (authChain *AuthenticationChain) queryRRset(ctx context.Context,
	zone string, qtype uint16) (rrsig *dns.RRSIG, rrset []dns.RR, err error) {
	customConn, err := authChain.dial(ctx, "", "")
	if err != nil {
		return nil, nil, err
	}
	conn := &dns.Conn{Conn: customConn}

	message := new(dns.Msg).SetQuestion(zone, qtype)
	response, _, err := authChain.client.ExchangeWithConn(message, conn)

	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	if err := conn.Close(); err != nil {
		return nil, nil, err
	}

	switch response.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return nil, nil, ErrNoResult
	default:
		return nil, nil, fmt.Errorf("%w: %d", dns.ErrRcode, response.Rcode)
	}

	rrset = make([]dns.RR, 0, len(response.Answer))

	for _, rr := range response.Answer {
		switch impl := rr.(type) { // TODO use header instead of type assertion?
		case *dns.RRSIG:
			rrsig = impl
		default:
			if rr != nil {
				rrset = append(rrset, rr)
			}
		}
	}

	return rrsig, rrset, nil
}

// func (sRRset *RRSet) IsSigned() bool {
// 	return sRRset.rrSig != nil
// }

// func (sRRset *RRSet) IsEmpty() bool {
// 	return len(sRRset.rrSet) == 0
// }

// func (sRRset *RRSet) SignerName() string {
// 	return sRRset.rrSig.SignerName
// }

// func NewSignedRRSet() *RRSet {
// 	return &RRSet{
// 		rrSet: make([]dns.RR, 0),
// 	}
// }
