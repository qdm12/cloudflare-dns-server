package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type signedZone struct {
	zone        string
	dnsKeyRRSig *dns.RRSIG
	dnsKeyRRSet []dns.RR
	dsRRSig     *dns.RRSIG
	dsRRSet     []dns.RR
	parent      *signedZone
	pubKeys     map[uint16]*dns.DNSKEY // key is the dns key tag

	// Mock fields
	timeNow func() time.Time
}

var (
	ErrRRNotDNSKey = errors.New("RR is not a DNS key")
)

func newSignedZone(zone string, dnsKeyRRSig, dsRRSig *dns.RRSIG,
	dnsKeyRRSet, dsRRSet []dns.RR) *signedZone {
	pubKeys := make(map[uint16]*dns.DNSKEY, len(dnsKeyRRSet))
	for _, rr := range dnsKeyRRSet {
		dnsKey, ok := rr.(*dns.DNSKEY)
		if !ok {
			// TODO error or continue?
			fmt.Println("Continuing debug 3213")
			continue
		}
		pubKeys[dnsKey.KeyTag()] = dnsKey
	}
	return &signedZone{
		zone:        zone,
		dnsKeyRRSig: dnsKeyRRSig,
		dnsKeyRRSet: dnsKeyRRSet,
		dsRRSig:     dsRRSig,
		dsRRSet:     dsRRSet,
		pubKeys:     pubKeys,
		timeNow:     time.Now,
	}
}

var (
	ErrPublicKeyNotFound = errors.New("public key not found")
	ErrVerification      = errors.New("failed verification")
	ErrRRSigExpired      = errors.New("RRSIG has expired")
)

func (sz *signedZone) verifyRRSIG(rrsig *dns.RRSIG, rrset []dns.RR) (err error) {
	keyTag := rrsig.KeyTag
	pubKey, ok := sz.pubKeys[keyTag]
	if !ok {
		return fmt.Errorf("%w: key tag %d", ErrPublicKeyNotFound, rrsig.KeyTag)
	}

	if !rrsig.ValidityPeriod(sz.timeNow()) {
		return ErrRRSigExpired
	}

	if err := rrsig.Verify(pubKey, rrset); err != nil {
		return fmt.Errorf("%w: %s", ErrVerification, err)
	}

	return nil
}

var (
	ErrResourceRecordNotDS = errors.New("resource record is not DS")
	ErrInvalidDS           = errors.New("DS RR record does not match DNS key")
	ErrUnknownDsDigestType = errors.New("unknown DS digest type")
)

// verifyDS validates the DS record against the KSK
// (key signing key) of the zone.
func (sz *signedZone) verifyDS(dsRrset []dns.RR) (err error) {
	for _, rr := range dsRrset {
		ds, ok := rr.(*dns.DS)
		if !ok {
			return fmt.Errorf("%w: %T", ErrResourceRecordNotDS, rr)
		}

		// if ds.DigestType != dns.SHA256 {
		// 	log.Printf("Unknown digest type (%d) on DS RR", ds.DigestType)
		// 	continue
		// }
		fmt.Println("DEBUG digest type: ", ds.DigestType)

		key, ok := sz.pubKeys[ds.KeyTag]
		if !ok {
			return fmt.Errorf("%w: key tag %d", ErrPublicKeyNotFound, ds.KeyTag)
		}

		storedDS := key.ToDS(ds.DigestType)
		if strings.EqualFold(ds.Digest, storedDS.Digest) {
			return nil
		}

		return ErrInvalidDS // TODO try next one?
	}
	return ErrUnknownDsDigestType // TODO remove
}
