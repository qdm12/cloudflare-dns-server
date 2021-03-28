package dnssec

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// AuthenticationChain represents the DNSSEC chain of trust from the
// queried zone to the root (.) zone.  In order for a zone to validate,
// it is required that each zone in the chain validate against its
// parent using the DS record.
//
// https://www.ietf.org/rfc/rfc4033.txt
type AuthenticationChain struct {
	client          *dns.Client
	dial            func(ctx context.Context, _, _ string) (net.Conn, error)
	delegationChain []*signedZone
}

// NewAuthenticationChain initializes an AuthenticationChain object and
// returns a reference to it.
func NewAuthenticationChain(client *dns.Client,
	dial func(ctx context.Context, _, _ string) (net.Conn, error)) *AuthenticationChain {
	return &AuthenticationChain{
		client: client,
		dial:   dial,
	}
}

// Populate queries the RRs required for the zone validation
// It begins the queries at the *domainName* zone and then walks
// up the delegation tree all the way up to the root zone, thus
// populating a linked list of SignedZone objects.
func (authChain *AuthenticationChain) Populate(ctx context.Context,
	zone string) (err error) {
	subZones := strings.Split(zone, ".")

	authChain.delegationChain = make([]*signedZone, 0, len(subZones))
	for i := range subZones {
		zoneName := dns.Fqdn(strings.Join(subZones[i:], "."))
		delegation, err := authChain.queryDelegation(ctx, zoneName)
		if err != nil {
			return err
		}

		if i > 0 {
			authChain.delegationChain[i-1].parent = delegation
		}
		authChain.delegationChain = append(authChain.delegationChain, delegation)
	}
	return nil
}

// queryDelegation takes a domain name and fetches the
// DS and DNSKEY records in that zone.
func (authChain *AuthenticationChain) queryDelegation(ctx context.Context,
	zone string) (signedZone *signedZone, err error) {
	dnsKeyRRSig, dnsKeyRRSet, err := authChain.queryRRset(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	} // TODO async with below

	dsRRSig, dsRRSet, err := authChain.queryRRset(ctx, zone, dns.TypeDS)
	if err != nil {
		return nil, err // TODO ignore?
	}

	return newSignedZone(zone, dnsKeyRRSig, dsRRSig, dnsKeyRRSet, dsRRSet), nil
}

// TODO add root anchors

// Verify uses the zone data in delegationChain to validate the DNSSEC
// chain of trust.
// It starts the verification in the RRSet supplied as parameter (verifies
// the RRSIG on the answer RRs), and, assuming a signature is correct and
// valid, it walks through the delegationChain checking the RRSIGs on
// the DNSKEY and DS resource record sets, as well as correctness of each
// delegation using the lower level methods in SignedZone.
func (authChain *AuthenticationChain) Verify(rrsig *dns.RRSIG, rrset []dns.RR) error {
	signedZone := authChain.delegationChain[0] // TODO idx safety

	if len(signedZone.dnsKeyRRSet) == 0 {
		return fmt.Errorf("%w: for zone %s", ErrNoDNSKey, signedZone.zone)
	}

	if err := signedZone.verifyRRSIG(rrsig, rrset); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidRRsig, err)
	}

	for _, signedZone := range authChain.delegationChain {
		if len(signedZone.dnsKeyRRSet) == 0 {
			return fmt.Errorf("%w: for zone %s", ErrNoDNSKey, signedZone.zone)
		}

		if signedZone.dnsKeyRRSig == nil {
			return fmt.Errorf("%w: for zone %s", ErrDnskeyNotAvailable, signedZone.zone)
		}

		err := signedZone.verifyRRSIG(signedZone.dnsKeyRRSig, signedZone.dnsKeyRRSet)
		if err != nil {
			return err
		}

		if signedZone.parent == nil {
			continue
		}

		// signed zone has a parent
		if len(signedZone.dsRRSet) == 0 {
			return fmt.Errorf("%w: on zone %s", ErrDsNotAvailable, signedZone.zone)
		}

		err = signedZone.parent.verifyRRSIG(signedZone.dsRRSig, signedZone.dsRRSet)
		if err != nil {
			return fmt.Errorf("%w: DS on zone %s for RRSIG key tag %d",
				ErrRRSIGValidation, signedZone.zone, signedZone.dsRRSig.KeyTag)
		}

		if err := signedZone.verifyDS(signedZone.dsRRSet); err != nil {
			return err
		}
	}
	return nil
}
