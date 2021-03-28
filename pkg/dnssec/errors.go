package dnssec

import (
	"errors"
)

// Errors returned by the verification/validation methods at all levels.
var (
	ErrResourceNotSigned   = errors.New("resource is not signed with RRSIG")
	ErrNoResult            = errors.New("requested RR not found")
	ErrNsNotAvailable      = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable  = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable      = errors.New("DS RR does not exist")
	ErrInvalidRRsig        = errors.New("invalid RRSIG")
	ErrRrsigValidityPeriod = errors.New("invalid RRSIG validity period")
	ErrInvalidQuery        = errors.New("invalid query input")
	ErrNoDNSKey            = errors.New("no DNS key")
	ErrRRSIGValidation     = errors.New("failed validating RR against RRSIG")
	ErrDSInvalid           = errors.New("invalid DS")
)
