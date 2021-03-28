package dnssec

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

var ErrUnexpectedRRSIGType = errors.New("unexpected RRSIG type")

func ExtractRRSIG(response *dns.Msg) (
	rrsig *dns.RRSIG, rrset []dns.RR, err error) {
	var ok bool
	rrset = make([]dns.RR, 0, len(response.Answer))
	for _, rr := range response.Answer {
		if rrsig == nil &&
			rr.Header().Rrtype == dns.TypeRRSIG {
			rrsig, ok = rr.(*dns.RRSIG)
			if !ok {
				return nil, rrset, fmt.Errorf("%w: %T", ErrUnexpectedRRSIGType, rr)
			}
			continue
		}
		rrset = append(rrset, rr)
	}
	return rrsig, rrset, nil
}
