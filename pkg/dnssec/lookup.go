package dnssec

// const MaxReturnedIPAddressesCount = 64

// func (resolver *Resolver) LookupIP(qname string) (ips []net.IP, err error) {

// 	if len(qname) < 1 {
// 		return nil, nil
// 	}

// 	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}

// 	answers := make([]*RRSet, 0, len(qtypes))

// 	for _, qtype := range qtypes {

// 		answer, err := queryRRset(qname, qtype)
// 		if answer == nil {
// 			continue
// 		}
// 		if err != nil {
// 			continue
// 		}
// 		if answer.IsEmpty() {
// 			continue
// 		}
// 		if !answer.IsSigned() {
// 			continue
// 		}

// 		answers = append(answers, answer)
// 	}

// 	if len(answers) < 1 {
// 		log.Printf("no results")
// 		return nil, ErrNoResult
// 	}

// 	signerName := answers[0].SignerName()
// 	authChain := NewAuthenticationChain()
// 	err = authChain.Populate(signerName)
// 	if err != nil {
// 		log.Printf("Cannot populate authentication chain: %s\n", err)
// 		return nil, err
// 	}
// 	resultIPs := make([]net.IP, MaxReturnedIPAddressesCount)
// 	for _, answer := range answers {
// 		err = authChain.Verify(answer)
// 		if err != nil {
// 			log.Printf("DNSSEC validation failed: %s\n", err)
// 			continue
// 		}
// 		ips := formatResultRRs(answer)
// 		resultIPs = append(resultIPs, ips...)
// 	}

// 	return resultIPs, nil
// }

// func formatResultRRs(signedRrset *RRSet) []net.IP {
// 	ips := make([]net.IP, 0, len(signedRrset.rrSet))
// 	for _, rr := range signedRrset.rrSet {
// 		switch t := rr.(type) {
// 		case *dns.A:
// 			ips = append(ips, t.A)
// 		case *dns.AAAA:
// 			ips = append(ips, t.AAAA)
// 		}
// 	}
// 	return ips
// }
